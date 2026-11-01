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

// Per-stage counters of the enter/exit pairing (sensor.stats): a record
// that never reaches the ring buffer shows where it was lost.
#define ST_STASH    0 // sys_enter stashed arguments
#define ST_TAKE_OK  1 // sys_exit found them, syscall succeeded
#define ST_MISSING  2 // sys_exit found nothing (evicted, or enter not seen)
#define ST_KIND     3 // sys_exit found another syscall's arguments
#define ST_FAILED   4 // syscall returned an error
#define ST_STASH_ERR 5 // map update failed
#define ST_N        6
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ST_N);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline void count(__u32 i)
{
	__u64 *n = bpf_map_lookup_elem(&stats, &i);
	if (n)
		__sync_fetch_and_add(n, 1);
}

static __always_inline int skip_self(void)
{
	__u32 zero = 0;
	__u32 *tgid = bpf_map_lookup_elem(&self, &zero);
	return tgid && *tgid == (bpf_get_current_pid_tgid() >> 32);
}

static __always_inline int enter_prctl(const unsigned long *args)
{
	if (args[0] != SELF_MAGIC)
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
	if (bpf_map_update_elem(&pending_args, &id, &p, BPF_ANY))
		count(ST_STASH_ERR);
	else
		count(ST_STASH);
}

// take returns the stashed arguments of this thread's syscall if it was
// of kind and succeeded; the entry is removed either way.
static __always_inline int take(__u32 kind, long ret, struct pending *out)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct pending *p = bpf_map_lookup_elem(&pending_args, &id);
	if (!p) {
		count(ST_MISSING);
		return 0;
	}
	int ok = p->kind == kind && ret >= 0;
	if (ok) {
		__builtin_memcpy(out, p, sizeof(*out));
		count(ST_TAKE_OK);
	} else {
		count(p->kind != kind ? ST_KIND : ST_FAILED);
	}
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

static __always_inline int enter_open(const unsigned long *args)
{
	open_enter(AT_FDCWD_, (const char *)args[0], args[1]);
	return 0;
}

static __always_inline int enter_creat(const unsigned long *args)
{
	open_enter(AT_FDCWD_, (const char *)args[0], O_CREAT_ | O_WRONLY_ | O_TRUNC_);
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

static __always_inline int enter_rename(const unsigned long *args)
{
	rename_enter(AT_FDCWD_, (const char *)args[0], AT_FDCWD_, (const char *)args[1]);
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

static __always_inline int enter_unlink(const unsigned long *args)
{
	unlink_enter(AT_FDCWD_, (const char *)args[0], 0);
	return 0;
}

#define AT_REMOVEDIR_ 0x200

static __always_inline int enter_rmdir(const unsigned long *args)
{
	unlink_enter(AT_FDCWD_, (const char *)args[0], AT_REMOVEDIR_);
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

static __always_inline int enter_delete_module(const unsigned long *args)
{
	stash(K_MODULE_DELETE, args[0], args[1], 0, 0);
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

static __always_inline int enter_ptrace(const unsigned long *args)
{
	long req = args[0];
	if (req != PTRACE_ATTACH_ && req != PTRACE_SEIZE_ && req != PTRACE_POKETEXT_ &&
	    req != PTRACE_POKEDATA_ && req != PTRACE_POKEUSER_ && req != PTRACE_SETREGS_)
		return 0;
	if (skip_self())
		return 0;
	stash(K_PTRACE, req, args[1], args[2], 0);
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

static __always_inline int enter_setuid(const unsigned long *args)
{
	setid_enter(ID_SETUID, args[0], 0, 0, 1);
	return 0;
}

static __always_inline int enter_setreuid(const unsigned long *args)
{
	setid_enter(ID_SETREUID, args[0], args[1], 0, 2);
	return 0;
}

static __always_inline int enter_setresuid(const unsigned long *args)
{
	setid_enter(ID_SETRESUID, args[0], args[1], args[2], 3);
	return 0;
}

static __always_inline int enter_setgid(const unsigned long *args)
{
	setid_enter(ID_SETGID, args[0], 0, 0, 1);
	return 0;
}

static __always_inline int enter_setregid(const unsigned long *args)
{
	setid_enter(ID_SETREGID, args[0], args[1], 0, 2);
	return 0;
}

static __always_inline int enter_setresgid(const unsigned long *args)
{
	setid_enter(ID_SETRESGID, args[0], args[1], args[2], 3);
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

static __always_inline int enter_capset(const unsigned long *args)
{
	if ((__u32)bpf_get_current_uid_gid() == 0)
		return 0;
	struct __user_cap_data_struct data = {};
	if (bpf_probe_read_user(&data, sizeof(data), (void *)args[1]) < 0)
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

static __always_inline int enter_memfd_create(const unsigned long *args)
{
	if (skip_self())
		return 0;
	stash(K_MEMFD, args[0], args[1], 0, 0);
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

// ─── syscall entry ───────────────────────────────────────────────────

// Arguments are stashed from one raw tracepoint on raw_syscalls/sys_enter,
// dispatched by syscall number, not from the per-syscall sys_enter_*
// tracepoints: on kernel 7.0 (GitHub's 7.0.0-azure) those did not run the
// program for some syscalls, a different set from run to run (openat,
// renameat2, unlinkat, then rmdir), so file events and ransomware canary
// hits were lost without an error. The sys_exit_* tracepoints were
// reliable and stay (the pairing counters in stats show it).
#if defined(__TARGET_ARCH_arm64)
// arm64's struct pt_regs starts with regs[31] (in an anonymous union with
// user_regs); CO-RE matches fields through anonymous members by name.
struct pt_regs___siem {
	__u64 regs[31];
} __attribute__((preserve_access_index));

#define NR_openat        56
#define NR_unlinkat      35
#define NR_renameat      38
#define NR_renameat2     276
#define NR_init_module   105
#define NR_finit_module  273
#define NR_prctl          167
#define NR_open           -2 // x86 only, never matches
#define NR_creat          -3 // x86 only, never matches
#define NR_rename         -4 // x86 only, never matches
#define NR_unlink         -5 // x86 only, never matches
#define NR_rmdir          -6 // x86 only, never matches
#define NR_delete_module  106
#define NR_ptrace         117
#define NR_setuid         146
#define NR_setreuid       145
#define NR_setresuid      147
#define NR_setgid         144
#define NR_setregid       143
#define NR_setresgid      149
#define NR_capset         91
#define NR_memfd_create   279
#else
#define NR_openat        257
#define NR_unlinkat      263
#define NR_renameat      264
#define NR_renameat2     316
#define NR_init_module   175
#define NR_finit_module  313
#define NR_prctl          157
#define NR_open           2
#define NR_creat          85
#define NR_rename         82
#define NR_unlink         87
#define NR_rmdir          84
#define NR_delete_module  176
#define NR_ptrace         101
#define NR_setuid         105
#define NR_setreuid       113
#define NR_setresuid      117
#define NR_setgid         106
#define NR_setregid       114
#define NR_setresgid      119
#define NR_capset         126
#define NR_memfd_create   319
#endif

SEC("raw_tracepoint/sys_enter")
int raw_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	long id = (long)ctx->args[1];
	switch (id) {
	case NR_openat:
	case NR_unlinkat:
	case NR_renameat:
	case NR_renameat2:
	case NR_init_module:
	case NR_finit_module:
	case NR_prctl:
	case NR_open:
	case NR_creat:
	case NR_rename:
	case NR_unlink:
	case NR_rmdir:
	case NR_delete_module:
	case NR_ptrace:
	case NR_setuid:
	case NR_setreuid:
	case NR_setresuid:
	case NR_setgid:
	case NR_setregid:
	case NR_setresgid:
	case NR_capset:
	case NR_memfd_create:
		break;
	default:
		return 0;
	}
	unsigned long a[4];
#if defined(__TARGET_ARCH_arm64)
	// The vendored vmlinux.h is x86's, so libbpf's arm64 PT_REGS_* macros
	// (struct user_pt_regs) do not compile; a local CO-RE flavour of arm64's
	// pt_regs is relocated against the running kernel's BTF instead. At
	// sys_enter x0..x3 still hold the arguments (x0 becomes the return value
	// only at exit).
	struct pt_regs___siem *regs = (struct pt_regs___siem *)ctx->args[0];
	a[0] = BPF_CORE_READ(regs, regs[0]);
	a[1] = BPF_CORE_READ(regs, regs[1]);
	a[2] = BPF_CORE_READ(regs, regs[2]);
	a[3] = BPF_CORE_READ(regs, regs[3]);
#else
	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	a[0] = PT_REGS_PARM1_CORE_SYSCALL(regs);
	a[1] = PT_REGS_PARM2_CORE_SYSCALL(regs);
	a[2] = PT_REGS_PARM3_CORE_SYSCALL(regs);
	a[3] = PT_REGS_PARM4_CORE_SYSCALL(regs);
#endif
	switch (id) {
	case NR_openat:
		open_enter(a[0], (const char *)a[1], a[2]);
		break;
	case NR_unlinkat:
		unlink_enter(a[0], (const char *)a[1], a[2]);
		break;
	case NR_renameat:
	case NR_renameat2:
		rename_enter(a[0], (const char *)a[1], a[2], (const char *)a[3]);
		break;
	case NR_init_module:
		stash(K_MODULE_INIT, a[1], a[2], 0, 0);
		break;
	case NR_finit_module:
		stash(K_MODULE_FINIT, a[0], a[1], a[2], 0);
		break;
	case NR_prctl:
		enter_prctl(a);
		break;
	case NR_open:
		enter_open(a);
		break;
	case NR_creat:
		enter_creat(a);
		break;
	case NR_rename:
		enter_rename(a);
		break;
	case NR_unlink:
		enter_unlink(a);
		break;
	case NR_rmdir:
		enter_rmdir(a);
		break;
	case NR_delete_module:
		enter_delete_module(a);
		break;
	case NR_ptrace:
		enter_ptrace(a);
		break;
	case NR_setuid:
		enter_setuid(a);
		break;
	case NR_setreuid:
		enter_setreuid(a);
		break;
	case NR_setresuid:
		enter_setresuid(a);
		break;
	case NR_setgid:
		enter_setgid(a);
		break;
	case NR_setregid:
		enter_setregid(a);
		break;
	case NR_setresgid:
		enter_setresgid(a);
		break;
	case NR_capset:
		enter_capset(a);
		break;
	case NR_memfd_create:
		enter_memfd_create(a);
		break;
	}
	return 0;
}
