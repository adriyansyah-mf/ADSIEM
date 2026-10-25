// prevent.bpf.c — execution prevention in the kernel (BPF LSM).
//
// lsm/bprm_check_security runs before a program (or a script, then its
// interpreter) is executed and can refuse it with -EPERM. Rules come from
// the agent through maps:
//
//   deny_path    exact executable path            → rule
//   deny_dir     (dev, inode) of a directory       → rule for anything below it
//   parent/child basename masks                    → rule when both match
//                (a web server starting a shell)
//
// Each rule has an action: detect (report only) or block. Hash rules need
// the file's content and are evaluated by the fanotify engine in Go.
#include "../../procexec/bpf/include/bpf/vmlinux.h"
#include "../../procexec/bpf/include/bpf/bpf_helpers.h"
#include "../../procexec/bpf/include/bpf/bpf_tracing.h"
#include "../../procexec/bpf/include/bpf/bpf_core_read.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM_     1
#define PATH_LEN   256
#define NAME_LEN   32
#define MAX_RULES  1024
#define MAX_PARENT 64

#define ACT_DETECT 1
#define ACT_BLOCK  2

#define HAS_PATH   1
#define HAS_DIR    2
#define HAS_PARENT 4

struct dir_key {
	__u64 ino;
	__u32 dev;
	__u32 pad;
};

// Keep in sync with decision in prevent_linux.go.
struct decision {
	__u64 ts;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u32 rule;
	__u32 action;
	char  comm[16];
	char  path[PATH_LEN];
	char  parent[NAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
	__type(key, __u32);
	__type(value, __u32); // action
} rule_action SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
	__type(key, char[PATH_LEN]);
	__type(value, __u32);
} deny_path SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
	__type(key, struct dir_key);
	__type(value, __u32);
} deny_dir SEC(".maps");

// Basename → bit set of parent rules it takes part in; bit k is rule
// parent_rule[k].
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
	__type(key, char[NAME_LEN]);
	__type(value, __u64);
} parent_mask SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_RULES);
	__type(key, char[NAME_LEN]);
	__type(value, __u64);
} child_mask SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PARENT);
	__type(key, __u32);
	__type(value, __u32);
} parent_rule SEC(".maps");

// [0] which rule kinds are loaded (HAS_*), [1] the agent's tgid.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u32);
} prevent_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} decisions SEC(".maps");

#define MAX_DEPTH 16
#define NAME_CAP  127
#define DIR_BUF   2048

struct scratch {
	__u64 name[MAX_DEPTH];
	__u32 len[MAX_DEPTH];
	char  buf[DIR_BUF * 2];
	char  key[PATH_LEN];
	char  base[NAME_LEN];
	char  pbase[NAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch);
} scratch_map SEC(".maps");

#define container_of(ptr, type, member) \
	((type *)((void *)(ptr) - bpf_core_field_offset(type, member)))

// build_path is the same two-loop walk as linsensor's (see its comment):
// the absolute path of (d, vm) into out, NUL padded to PATH_LEN.
static __always_inline void build_path(struct scratch *s, struct dentry *d, struct vfsmount *vm, char *out)
{
	struct mount *mnt = container_of(vm, struct mount, mnt);
	int done = 0;
	for (int i = 0; i < MAX_DEPTH; i++) {
		s->name[i] = 0;
		s->len[i] = 0;
		if (done)
			continue;
		struct dentry *mnt_root = BPF_CORE_READ(vm, mnt_root);
		struct dentry *parent = BPF_CORE_READ(d, d_parent);
		if (d == mnt_root) {
			struct mount *mp = BPF_CORE_READ(mnt, mnt_parent);
			if (mp == mnt) {
				done = 1;
				continue;
			}
			d = BPF_CORE_READ(mnt, mnt_mountpoint);
			mnt = mp;
			vm = (struct vfsmount *)((void *)mnt + bpf_core_field_offset(struct mount, mnt));
			continue;
		}
		struct qstr q = BPF_CORE_READ(d, d_name);
		if (d == parent) {
			if (i == 0) {
				s->name[0] = (__u64)q.name;
				s->len[0] = q.len;
			}
			done = 1;
			continue;
		}
		s->name[i] = (__u64)q.name;
		s->len[i] = q.len;
		d = parent;
	}
	__u32 pos = DIR_BUF;
	s->buf[DIR_BUF] = 0;
	for (int i = 0; i < MAX_DEPTH; i++) {
		__u32 len = s->len[i];
		if (len > NAME_CAP)
			len = NAME_CAP;
		__u32 has = (len + NAME_CAP) >> 7;
		pos -= len;
		bpf_probe_read_kernel(&s->buf[pos & (DIR_BUF - 1)], len & NAME_CAP, (const void *)s->name[i]);
		s->buf[(pos - 1) & (DIR_BUF - 1)] = '/';
		pos -= has;
	}
	__builtin_memset(out, 0, PATH_LEN);
	if (pos == DIR_BUF) {
		out[0] = '/';
		return;
	}
	bpf_probe_read_kernel_str(out, PATH_LEN, &s->buf[pos & (DIR_BUF - 1)]);
}

static __always_inline void basename_of(struct dentry *d, char *out)
{
	__builtin_memset(out, 0, NAME_LEN);
	const unsigned char *name = BPF_CORE_READ(d, d_name.name);
	bpf_probe_read_kernel_str(out, NAME_LEN, name);
}

// in_denied_dir walks the directories above d (across mounts) and returns
// the rule of the first one in deny_dir, or -1.
static __always_inline long in_denied_dir(struct dentry *d, struct vfsmount *vm)
{
	struct mount *mnt = container_of(vm, struct mount, mnt);
	d = BPF_CORE_READ(d, d_parent);
	for (int i = 0; i < MAX_DEPTH; i++) {
		struct dir_key k = {
			.ino = BPF_CORE_READ(d, d_inode, i_ino),
			.dev = BPF_CORE_READ(d, d_sb, s_dev),
		};
		__u32 *rule = bpf_map_lookup_elem(&deny_dir, &k);
		if (rule)
			return *rule;
		struct dentry *mnt_root = BPF_CORE_READ(vm, mnt_root);
		struct dentry *parent = BPF_CORE_READ(d, d_parent);
		if (d == mnt_root) {
			struct mount *mp = BPF_CORE_READ(mnt, mnt_parent);
			if (mp == mnt)
				return -1;
			d = BPF_CORE_READ(mnt, mnt_mountpoint);
			mnt = mp;
			vm = (struct vfsmount *)((void *)mnt + bpf_core_field_offset(struct mount, mnt));
			continue;
		}
		if (d == parent)
			return -1;
		d = parent;
	}
	return -1;
}

static __always_inline long parent_child_rule(struct scratch *s)
{
	__u64 *cm = bpf_map_lookup_elem(&child_mask, s->base);
	if (!cm)
		return -1;
	__u64 *pm = bpf_map_lookup_elem(&parent_mask, s->pbase);
	if (!pm)
		return -1;
	__u64 m = *cm & *pm;
	for (__u32 k = 0; k < MAX_PARENT; k++) {
		if ((m >> k) & 1) {
			__u32 *rule = bpf_map_lookup_elem(&parent_rule, &k);
			return rule ? (long)*rule : -1;
		}
	}
	return -1;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(check_exec, struct linux_binprm *bprm)
{
	__u32 zero = 0, one = 1;
	__u32 *has = bpf_map_lookup_elem(&prevent_config, &zero);
	if (!has || *has == 0)
		return 0;
	__u32 *self = bpf_map_lookup_elem(&prevent_config, &one);
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (self && *self == (pid_tgid >> 32))
		return 0; // never stand in the agent's way
	struct scratch *s = bpf_map_lookup_elem(&scratch_map, &zero);
	if (!s)
		return 0;

	struct file *f = BPF_CORE_READ(bprm, file);
	struct dentry *d = BPF_CORE_READ(f, f_path.dentry);
	struct vfsmount *vm = BPF_CORE_READ(f, f_path.mnt);
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct dentry *pd = BPF_CORE_READ(task, mm, exe_file, f_path.dentry);

	long rule = -1;
	build_path(s, d, vm, s->key);
	basename_of(d, s->base);
	basename_of(pd, s->pbase);
	if (*has & HAS_PATH) {
		__u32 *r = bpf_map_lookup_elem(&deny_path, s->key);
		if (r)
			rule = *r;
	}
	if (rule < 0 && (*has & HAS_DIR))
		rule = in_denied_dir(d, vm);
	if (rule < 0 && (*has & HAS_PARENT))
		rule = parent_child_rule(s);
	if (rule < 0)
		return 0;

	__u32 idx = (__u32)rule;
	__u32 *act = bpf_map_lookup_elem(&rule_action, &idx);
	__u32 action = act ? *act : ACT_DETECT;
	struct decision *ev = bpf_ringbuf_reserve(&decisions, sizeof(*ev), 0);
	if (ev) {
		ev->ts = bpf_ktime_get_ns();
		ev->pid = (__u32)pid_tgid;
		ev->tgid = pid_tgid >> 32;
		ev->ppid = BPF_CORE_READ(task, real_parent, tgid);
		ev->uid = (__u32)bpf_get_current_uid_gid();
		ev->rule = idx;
		ev->action = action;
		bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
		__builtin_memcpy(ev->path, s->key, PATH_LEN);
		__builtin_memcpy(ev->parent, s->pbase, NAME_LEN);
		bpf_ringbuf_submit(ev, 0);
	}
	return action == ACT_BLOCK ? -EPERM_ : 0;
}

// The agent's tgid as the kernel numbers it, learnt from prctl(SELF_MAGIC)
// like linsensor does (os.Getpid is wrong in a container).
#define SELF_MAGIC 0x50524556 // "PREV"

SEC("tracepoint/syscalls/sys_enter_prctl")
int enter_prctl(struct trace_event_raw_sys_enter *ctx)
{
	if (ctx->args[0] != SELF_MAGIC)
		return 0;
	__u32 one = 1;
	__u32 *self = bpf_map_lookup_elem(&prevent_config, &one);
	if (self && *self == 0)
		*self = bpf_get_current_pid_tgid() >> 32;
	return 0;
}
