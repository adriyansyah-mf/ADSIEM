// linsensor.bpf.c — Linux host telemetry beyond exec and network:
//
//   file writes      openat/open/creat opened for writing, renameat(2)/rename,
//                    unlinkat/unlink
//   kernel modules   init_module, finit_module, delete_module
//   ptrace           attach, seize, poke and setregs (injection primitives)
//   privilege gain   set*uid / set*gid to 0 by a non-root caller, capset by a
//                    non-root caller
//   memfd            memfd_create, and exec of a memfd or deleted file
//   process exit     thread-group leader exit with its exit code
//
// Syscalls are reported at sys_exit and only when they succeeded: sys_enter
// stashes the arguments per thread, sys_exit reads the user strings (still
// mapped, same thread) and emits one record. Tracepoints only; the x86-only
// open/creat/rename/unlink tracepoints do not exist on arm64, where the
// loader skips them.
#include "procexec/bpf/include/bpf/vmlinux.h"
#include "procexec/bpf/include/bpf/bpf_helpers.h"
#include "procexec/bpf/include/bpf/bpf_tracing.h"
#include "procexec/bpf/include/bpf/bpf_core_read.h"

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define PATH_LEN      256

#define AT_FDCWD_     -100
#define O_WRONLY_     01
#define O_RDWR_       02
#define O_CREAT_      0100
#define O_TRUNC_      01000

// Event kinds; keep in sync with kind* in linsensor.go.
#define K_OPEN          1
#define K_RENAME        2
#define K_UNLINK        3
#define K_MODULE_INIT   4
#define K_MODULE_FINIT  5
#define K_MODULE_DELETE 6
#define K_PTRACE        7
#define K_SETID         8
#define K_CAPSET        9
#define K_MEMFD         10
#define K_EXEC          11
#define K_FILELESS_EXEC 12
#define K_EXIT          13

// Which set*id call a K_SETID record came from (arg0).
#define ID_SETUID    1
#define ID_SETREUID  2
#define ID_SETRESUID 3
#define ID_SETGID    4
#define ID_SETREGID  5
#define ID_SETRESGID 6

// Keep in sync with decodeEvent in linsensor.go.
struct sensor_event {
	__u64 ts;
	__s64 ret;
	__u64 arg0;
	__u64 arg1;
	__u64 arg2;
	__u32 kind;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u32 euid;
	__s32 dfd;
	__s32 dfd2;
	char  comm[TASK_COMM_LEN];
	char  path[PATH_LEN];
	char  path2[PATH_LEN];
	// Directories that relative path / path2 are relative to, resolved
	// here: a short-lived process's /proc entry is gone by the time the
	// agent reads the record.
	char  dir[PATH_LEN];
	char  dir2[PATH_LEN];
};

struct pending {
	__u32 kind;
	__u32 pad;
	__u64 a[4];
	__u32 uid, euid; // the caller's ids at sys_enter (set*id changes them)
};

// The agent's own tgid in the initial pid namespace: its writes are not
// reported (they would feed back into themselves). The loader cannot know
// that pid when it runs in a container, so it calls prctl(SELF_MAGIC)
// once and enter_prctl records the caller.
#define SELF_MAGIC 0x4c53454e // "LSEN", not a prctl option
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} self SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} sensor_events SEC(".maps");

// build_path writes the absolute path of (dentry, vfsmount) into out,
// crossing mount points, at most MAX_DEPTH components; a component name
// is cut at NAME_CAP bytes. A path above the mount namespace's root (a
// container) is relative to that root.
//
// Two loops keep the verifier linear: the first only collects name
// pointers (its branches leave nothing precise behind, so states merge),
// the second writes backwards without branching.
#define MAX_DEPTH 16
#define NAME_CAP  127
#define DIR_BUF   2048 // half of the scratch; masked offsets stay inside

struct path_parts {
	__u64 name[MAX_DEPTH];
	__u32 len[MAX_DEPTH];
	char  buf[DIR_BUF * 2];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct path_parts);
} path_scratch SEC(".maps");

#define container_of(ptr, type, member) \
	((type *)((void *)(ptr) - bpf_core_field_offset(type, member)))

static __always_inline void build_path(struct dentry *d, struct vfsmount *vm, char *out)
{
	__u32 zero = 0;
	struct path_parts *pp = bpf_map_lookup_elem(&path_scratch, &zero);
	if (!pp || !d || !vm)
		return;
	struct mount *mnt = container_of(vm, struct mount, mnt);
	int done = 0;
	for (int i = 0; i < MAX_DEPTH; i++) {
		pp->name[i] = 0;
		pp->len[i] = 0;
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
			// A disconnected dentry (memfd, other pseudo files) is its
			// own parent: report its name, as d_path does.
			if (i == 0) {
				pp->name[0] = (__u64)q.name;
				pp->len[0] = q.len;
			}
			done = 1;
			continue;
		}
		pp->name[i] = (__u64)q.name;
		pp->len[i] = q.len;
		d = parent;
	}
	__u32 pos = DIR_BUF;
	pp->buf[DIR_BUF] = 0;
	for (int i = 0; i < MAX_DEPTH; i++) {
		__u32 len = pp->len[i];
		if (len > NAME_CAP)
			len = NAME_CAP;
		__u32 has = (len + NAME_CAP) >> 7; // 0 for an empty slot, else 1
		pos -= len;
		bpf_probe_read_kernel(&pp->buf[pos & (DIR_BUF - 1)], len & NAME_CAP, (const void *)pp->name[i]);
		pp->buf[(pos - 1) & (DIR_BUF - 1)] = '/';
		pos -= has;
	}
	if (pos == DIR_BUF) {
		out[0] = '/';
		out[1] = 0;
		return;
	}
	bpf_probe_read_kernel_str(out, PATH_LEN, &pp->buf[pos & (DIR_BUF - 1)]);
}

static __always_inline struct file *fd_file(int fd)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	unsigned int max = BPF_CORE_READ(fdt, max_fds);
	if (fd < 0 || (unsigned int)fd >= max)
		return NULL;
	struct file **fds = BPF_CORE_READ(fdt, fd);
	struct file *f = NULL;
	bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]);
	return f;
}

// dir_of writes the directory a relative path given with dfd starts at.
static __always_inline void dir_of(int dfd, char *out)
{
	struct dentry *d = NULL;
	struct vfsmount *vm = NULL;
	if (dfd == AT_FDCWD_) {
		struct task_struct *task = (struct task_struct *)bpf_get_current_task();
		struct fs_struct *fs = BPF_CORE_READ(task, fs);
		d = BPF_CORE_READ(fs, pwd.dentry);
		vm = BPF_CORE_READ(fs, pwd.mnt);
	} else {
		struct file *f = fd_file(dfd);
		if (!f)
			return;
		d = BPF_CORE_READ(f, f_path.dentry);
		vm = BPF_CORE_READ(f, f_path.mnt);
	}
	build_path(d, vm, out);
}

// Records lost because the ring buffer was full.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

// Arguments stashed at sys_enter, keyed by pid_tgid.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct pending);
} pending_args SEC(".maps");

static __always_inline int skip_self(void)
{
	__u32 zero = 0;
	__u32 *tgid = bpf_map_lookup_elem(&self, &zero);
	return tgid && *tgid == (bpf_get_current_pid_tgid() >> 32);
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int enter_prctl(struct trace_event_raw_sys_enter *ctx)
{
	if (ctx->args[0] != SELF_MAGIC)
		return 0;
	__u32 zero = 0;
	__u32 *tgid = bpf_map_lookup_elem(&self, &zero);
	if (tgid && *tgid == 0)
		*tgid = bpf_get_current_pid_tgid() >> 32;
	return 0;
}

static __always_inline struct sensor_event *reserve(__u32 kind)
{
	struct sensor_event *ev = bpf_ringbuf_reserve(&sensor_events, sizeof(*ev), 0);
	if (!ev) {
		__u32 zero = 0;
		__u64 *n = bpf_map_lookup_elem(&drops, &zero);
		if (n)
			__sync_fetch_and_add(n, 1);
		return NULL;
	}
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	ev->ts = bpf_ktime_get_ns();
	ev->ret = 0;
	ev->arg0 = 0;
	ev->arg1 = 0;
	ev->arg2 = 0;
	ev->kind = kind;
	ev->pid = (__u32)pid_tgid;
	ev->tgid = pid_tgid >> 32;
	ev->ppid = BPF_CORE_READ(task, real_parent, tgid);
	ev->uid = (__u32)uid_gid;
	ev->euid = BPF_CORE_READ(task, cred, euid.val);
	ev->dfd = AT_FDCWD_;
	ev->dfd2 = AT_FDCWD_;
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
	ev->path[0] = 0;
	ev->path2[0] = 0;
	ev->dir[0] = 0;
	ev->dir2[0] = 0;
	return ev;
}

static __always_inline void stash(__u32 kind, __u64 a0, __u64 a1, __u64 a2, __u64 a3)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct pending p = {.kind = kind, .a = {a0, a1, a2, a3}};
	bpf_map_update_elem(&pending_args, &id, &p, BPF_ANY);
}

// take returns the stashed arguments of this thread's syscall if it was
// of kind and succeeded; the entry is removed either way.
static __always_inline int take(__u32 kind, long ret, struct pending *out)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct pending *p = bpf_map_lookup_elem(&pending_args, &id);
	if (!p)
		return 0;
	int ok = p->kind == kind && ret >= 0;
	if (ok)
		__builtin_memcpy(out, p, sizeof(*out));
	bpf_map_delete_elem(&pending_args, &id);
	return ok;
}

// ─── file writes ─────────────────────────────────────────────────────

static __always_inline void open_enter(long dfd, const char *name, long flags)
{
	if (skip_self())
		return;
	if (!(flags & (O_WRONLY_ | O_RDWR_ | O_CREAT_ | O_TRUNC_)))
		return;
	stash(K_OPEN, dfd, (__u64)name, flags, 0);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	open_enter(ctx->args[0], (const char *)ctx->args[1], ctx->args[2]);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int enter_open(struct trace_event_raw_sys_enter *ctx)
{
	open_enter(AT_FDCWD_, (const char *)ctx->args[0], ctx->args[1]);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int enter_creat(struct trace_event_raw_sys_enter *ctx)
{
	open_enter(AT_FDCWD_, (const char *)ctx->args[0], O_CREAT_ | O_WRONLY_ | O_TRUNC_);
	return 0;
}

static __always_inline void open_exit(long ret)
{
	struct pending p;
	if (!take(K_OPEN, ret, &p))
		return;
	struct sensor_event *ev = reserve(K_OPEN);
	if (!ev)
		return;
	ev->ret = ret;
	ev->dfd = (__s32)p.a[0];
	ev->arg0 = p.a[2];
	bpf_probe_read_user_str(ev->path, sizeof(ev->path), (const char *)p.a[1]);
	if (ev->path[0] != '/')
		dir_of(ev->dfd, ev->dir);
	bpf_ringbuf_submit(ev, 0);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int exit_openat(struct trace_event_raw_sys_exit *ctx)
{
	open_exit(ctx->ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int exit_open(struct trace_event_raw_sys_exit *ctx)
{
	open_exit(ctx->ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_creat")
int exit_creat(struct trace_event_raw_sys_exit *ctx)
{
	open_exit(ctx->ret);
	return 0;
}

static __always_inline void rename_enter(long olddfd, const char *old, long newdfd, const char *new)
{
	if (skip_self())
		return;
	stash(K_RENAME, olddfd, (__u64)old, newdfd, (__u64)new);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int enter_renameat(struct trace_event_raw_sys_enter *ctx)
{
	rename_enter(ctx->args[0], (const char *)ctx->args[1], ctx->args[2], (const char *)ctx->args[3]);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int enter_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	rename_enter(ctx->args[0], (const char *)ctx->args[1], ctx->args[2], (const char *)ctx->args[3]);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int enter_rename(struct trace_event_raw_sys_enter *ctx)
{
	rename_enter(AT_FDCWD_, (const char *)ctx->args[0], AT_FDCWD_, (const char *)ctx->args[1]);
	return 0;
}

static __always_inline void rename_exit(long ret)
{
	struct pending p;
	if (!take(K_RENAME, ret, &p))
		return;
	struct sensor_event *ev = reserve(K_RENAME);
	if (!ev)
		return;
	ev->ret = ret;
	ev->dfd = (__s32)p.a[0];
	ev->dfd2 = (__s32)p.a[2];
	bpf_probe_read_user_str(ev->path, sizeof(ev->path), (const char *)p.a[1]);
	if (ev->path[0] != '/')
		dir_of(ev->dfd, ev->dir);
	bpf_probe_read_user_str(ev->path2, sizeof(ev->path2), (const char *)p.a[3]);
	if (ev->path2[0] != '/')
		dir_of(ev->dfd2, ev->dir2);
	bpf_ringbuf_submit(ev, 0);
}

SEC("tracepoint/syscalls/sys_exit_renameat")
int exit_renameat(struct trace_event_raw_sys_exit *ctx)
{
	rename_exit(ctx->ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int exit_renameat2(struct trace_event_raw_sys_exit *ctx)
{
	rename_exit(ctx->ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_rename")
int exit_rename(struct trace_event_raw_sys_exit *ctx)
{
	rename_exit(ctx->ret);
	return 0;
}

static __always_inline void unlink_enter(long dfd, const char *name, long flags)
{
	if (skip_self())
		return;
	stash(K_UNLINK, dfd, (__u64)name, flags, 0);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	unlink_enter(ctx->args[0], (const char *)ctx->args[1], ctx->args[2]);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int enter_unlink(struct trace_event_raw_sys_enter *ctx)
{
	unlink_enter(AT_FDCWD_, (const char *)ctx->args[0], 0);
	return 0;
}

#define AT_REMOVEDIR_ 0x200

SEC("tracepoint/syscalls/sys_enter_rmdir")
int enter_rmdir(struct trace_event_raw_sys_enter *ctx)
{
	unlink_enter(AT_FDCWD_, (const char *)ctx->args[0], AT_REMOVEDIR_);
	return 0;
}

static __always_inline void unlink_exit(long ret)
{
	struct pending p;
	if (!take(K_UNLINK, ret, &p))
		return;
	struct sensor_event *ev = reserve(K_UNLINK);
	if (!ev)
		return;
	ev->ret = ret;
	ev->dfd = (__s32)p.a[0];
	ev->arg0 = p.a[2];
	bpf_probe_read_user_str(ev->path, sizeof(ev->path), (const char *)p.a[1]);
	if (ev->path[0] != '/')
		dir_of(ev->dfd, ev->dir);
	bpf_ringbuf_submit(ev, 0);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int exit_unlinkat(struct trace_event_raw_sys_exit *ctx)
{
	unlink_exit(ctx->ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int exit_unlink(struct trace_event_raw_sys_exit *ctx)
{
	unlink_exit(ctx->ret);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_rmdir")
int exit_rmdir(struct trace_event_raw_sys_exit *ctx)
{
	unlink_exit(ctx->ret);
	return 0;
}

// ─── kernel modules ──────────────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_init_module")
int enter_init_module(struct trace_event_raw_sys_enter *ctx)
{
	stash(K_MODULE_INIT, ctx->args[1], ctx->args[2], 0, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_init_module")
int exit_init_module(struct trace_event_raw_sys_exit *ctx)
{
	struct pending p;
	if (!take(K_MODULE_INIT, ctx->ret, &p))
		return 0;
	struct sensor_event *ev = reserve(K_MODULE_INIT);
	if (!ev)
		return 0;
	ev->arg0 = p.a[0]; // image length
	bpf_probe_read_user_str(ev->path2, sizeof(ev->path2), (const char *)p.a[1]);
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int enter_finit_module(struct trace_event_raw_sys_enter *ctx)
{
	stash(K_MODULE_FINIT, ctx->args[0], ctx->args[1], ctx->args[2], 0);
	return 0;
}


SEC("tracepoint/syscalls/sys_exit_finit_module")
int exit_finit_module(struct trace_event_raw_sys_exit *ctx)
{
	struct pending p;
	if (!take(K_MODULE_FINIT, ctx->ret, &p))
		return 0;
	struct sensor_event *ev = reserve(K_MODULE_FINIT);
	if (!ev)
		return 0;
	ev->dfd = (__s32)p.a[0];
	ev->arg0 = p.a[2]; // flags
	struct file *f = fd_file((int)p.a[0]);
	if (f)
		build_path(BPF_CORE_READ(f, f_path.dentry), BPF_CORE_READ(f, f_path.mnt), ev->path);
	bpf_probe_read_user_str(ev->path2, sizeof(ev->path2), (const char *)p.a[1]);
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int enter_delete_module(struct trace_event_raw_sys_enter *ctx)
{
	stash(K_MODULE_DELETE, ctx->args[0], ctx->args[1], 0, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_delete_module")
int exit_delete_module(struct trace_event_raw_sys_exit *ctx)
{
	struct pending p;
	if (!take(K_MODULE_DELETE, ctx->ret, &p))
		return 0;
	struct sensor_event *ev = reserve(K_MODULE_DELETE);
	if (!ev)
		return 0;
	ev->arg0 = p.a[1];
	bpf_probe_read_user_str(ev->path, sizeof(ev->path), (const char *)p.a[0]);
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

// ─── ptrace ──────────────────────────────────────────────────────────

#define PTRACE_POKETEXT_ 4
#define PTRACE_POKEDATA_ 5
#define PTRACE_POKEUSER_ 6
#define PTRACE_SETREGS_  13
#define PTRACE_ATTACH_   16
#define PTRACE_SEIZE_    0x4206

SEC("tracepoint/syscalls/sys_enter_ptrace")
int enter_ptrace(struct trace_event_raw_sys_enter *ctx)
{
	long req = ctx->args[0];
	if (req != PTRACE_ATTACH_ && req != PTRACE_SEIZE_ && req != PTRACE_POKETEXT_ &&
	    req != PTRACE_POKEDATA_ && req != PTRACE_POKEUSER_ && req != PTRACE_SETREGS_)
		return 0;
	if (skip_self())
		return 0;
	stash(K_PTRACE, req, ctx->args[1], ctx->args[2], 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_ptrace")
int exit_ptrace(struct trace_event_raw_sys_exit *ctx)
{
	struct pending p;
	if (!take(K_PTRACE, ctx->ret, &p))
		return 0;
	struct sensor_event *ev = reserve(K_PTRACE);
	if (!ev)
		return 0;
	ev->arg0 = p.a[0]; // request
	ev->arg1 = p.a[1]; // target pid
	ev->arg2 = p.a[2]; // address
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

// ─── privilege gain ──────────────────────────────────────────────────

// setid_enter stashes a set*id call that sets some id to 0 (root) while
// the caller's real uid is not 0. -1 (unchanged) is not 0.
static __always_inline void setid_enter(__u64 which, __u32 a, __u32 b, __u32 c, int n)
{
	if ((__u32)bpf_get_current_uid_gid() == 0)
		return;
	int to_root = a == 0 || (n > 1 && b == 0) || (n > 2 && c == 0);
	if (!to_root)
		return;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 id = bpf_get_current_pid_tgid();
	struct pending p = {
		.kind = K_SETID, .a = {which, a, b, c},
		.uid = (__u32)bpf_get_current_uid_gid(), .euid = BPF_CORE_READ(task, cred, euid.val),
	};
	bpf_map_update_elem(&pending_args, &id, &p, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int enter_setuid(struct trace_event_raw_sys_enter *ctx)
{
	setid_enter(ID_SETUID, ctx->args[0], 0, 0, 1);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int enter_setreuid(struct trace_event_raw_sys_enter *ctx)
{
	setid_enter(ID_SETREUID, ctx->args[0], ctx->args[1], 0, 2);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int enter_setresuid(struct trace_event_raw_sys_enter *ctx)
{
	setid_enter(ID_SETRESUID, ctx->args[0], ctx->args[1], ctx->args[2], 3);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int enter_setgid(struct trace_event_raw_sys_enter *ctx)
{
	setid_enter(ID_SETGID, ctx->args[0], 0, 0, 1);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int enter_setregid(struct trace_event_raw_sys_enter *ctx)
{
	setid_enter(ID_SETREGID, ctx->args[0], ctx->args[1], 0, 2);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int enter_setresgid(struct trace_event_raw_sys_enter *ctx)
{
	setid_enter(ID_SETRESGID, ctx->args[0], ctx->args[1], ctx->args[2], 3);
	return 0;
}

static __always_inline void setid_exit(long ret)
{
	struct pending p;
	if (!take(K_SETID, ret, &p))
		return;
	struct sensor_event *ev = reserve(K_SETID);
	if (!ev)
		return;
	ev->arg0 = p.a[0];
	ev->arg1 = p.a[1] | (p.a[2] << 32); // first two ids
	ev->arg2 = p.a[3];
	ev->uid = p.uid; // who asked, not who it became
	ev->euid = p.euid;
	bpf_ringbuf_submit(ev, 0);
}

SEC("tracepoint/syscalls/sys_exit_setuid")
int exit_setuid(struct trace_event_raw_sys_exit *ctx) { setid_exit(ctx->ret); return 0; }
SEC("tracepoint/syscalls/sys_exit_setreuid")
int exit_setreuid(struct trace_event_raw_sys_exit *ctx) { setid_exit(ctx->ret); return 0; }
SEC("tracepoint/syscalls/sys_exit_setresuid")
int exit_setresuid(struct trace_event_raw_sys_exit *ctx) { setid_exit(ctx->ret); return 0; }
SEC("tracepoint/syscalls/sys_exit_setgid")
int exit_setgid(struct trace_event_raw_sys_exit *ctx) { setid_exit(ctx->ret); return 0; }
SEC("tracepoint/syscalls/sys_exit_setregid")
int exit_setregid(struct trace_event_raw_sys_exit *ctx) { setid_exit(ctx->ret); return 0; }
SEC("tracepoint/syscalls/sys_exit_setresgid")
int exit_setresgid(struct trace_event_raw_sys_exit *ctx) { setid_exit(ctx->ret); return 0; }

SEC("tracepoint/syscalls/sys_enter_capset")
int enter_capset(struct trace_event_raw_sys_enter *ctx)
{
	if ((__u32)bpf_get_current_uid_gid() == 0)
		return 0;
	struct __user_cap_data_struct data = {};
	if (bpf_probe_read_user(&data, sizeof(data), (void *)ctx->args[1]) < 0)
		return 0;
	if (!data.effective)
		return 0;
	stash(K_CAPSET, data.effective, data.permitted, 0, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_capset")
int exit_capset(struct trace_event_raw_sys_exit *ctx)
{
	struct pending p;
	if (!take(K_CAPSET, ctx->ret, &p))
		return 0;
	struct sensor_event *ev = reserve(K_CAPSET);
	if (!ev)
		return 0;
	ev->arg0 = p.a[0]; // effective
	ev->arg1 = p.a[1]; // permitted
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

// ─── memfd and fileless exec ─────────────────────────────────────────

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int enter_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
	if (skip_self())
		return 0;
	stash(K_MEMFD, ctx->args[0], ctx->args[1], 0, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_memfd_create")
int exit_memfd_create(struct trace_event_raw_sys_exit *ctx)
{
	struct pending p;
	if (!take(K_MEMFD, ctx->ret, &p))
		return 0;
	struct sensor_event *ev = reserve(K_MEMFD);
	if (!ev)
		return 0;
	ev->ret = ctx->ret;
	ev->arg0 = p.a[1]; // flags
	bpf_probe_read_user_str(ev->path, sizeof(ev->path), (const char *)p.a[0]);
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

// Every exec is reported (the Go side drops its cached image for the pid);
// one whose executable is a memfd or an unlinked file is K_FILELESS_EXEC.
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	if (skip_self())
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct file *exe = BPF_CORE_READ(task, mm, exe_file);
	unsigned int nlink = BPF_CORE_READ(exe, f_inode, __i_nlink);
	const unsigned char *name = BPF_CORE_READ(exe, f_path.dentry, d_name.name);
	char head[6] = {};
	bpf_probe_read_kernel(head, sizeof(head), name);
	int memfd = head[0] == 'm' && head[1] == 'e' && head[2] == 'm' && head[3] == 'f' &&
		    head[4] == 'd' && head[5] == ':';
	struct sensor_event *ev = reserve(memfd || nlink == 0 ? K_FILELESS_EXEC : K_EXEC);
	if (!ev)
		return 0;
	ev->arg0 = nlink;
	// The full executable path, so Image is known even after the
	// process has exited (/proc/<pid>/exe is gone by then).
	build_path(BPF_CORE_READ(exe, f_path.dentry), BPF_CORE_READ(exe, f_path.mnt), ev->path);
	unsigned int loc = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_kernel_str(ev->path2, sizeof(ev->path2), (void *)ctx + loc);
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

// ─── process exit ────────────────────────────────────────────────────

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if ((__u32)pid_tgid != (pid_tgid >> 32) || skip_self())
		return 0; // only the thread-group leader
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct sensor_event *ev = reserve(K_EXIT);
	if (!ev)
		return 0;
	ev->arg0 = BPF_CORE_READ(task, exit_code);
	bpf_ringbuf_submit(ev, 0);
	return 0;
}
