// execve.bpf.c — attaches to tracepoint/syscalls/sys_enter_execve to capture
// process exec events (Image, CommandLine, PPID/ParentImage, UID) for the
// Sigma "process_creation" logsource. Fires at syscall entry (pre-exec) so
// argv is still readable from the calling process's user memory.
//
// ParentImage is best-effort: a small LRU cache maps pid -> last exec'd
// filename, keyed on this program's own events, so a lookup by ppid only
// resolves if we've already observed the parent's own exec (init/systemd
// and processes that started before the agent won't resolve).
#include "include/bpf/vmlinux.h"
#include "include/bpf/bpf_helpers.h"
#include "include/bpf/bpf_tracing.h"
#include "include/bpf/bpf_core_read.h"

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN     16
#define MAX_FILENAME_LEN  256
#define ARGSIZE           128
#define MAXARG            8
#define ARGS_BUF_LEN      (ARGSIZE * MAXARG)

struct exec_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	char  comm[TASK_COMM_LEN];
	char  filename[MAX_FILENAME_LEN];
	char  parent_filename[MAX_FILENAME_LEN];
	char  args[ARGS_BUF_LEN];   // argv strings, NUL-separated
	__u32 args_size;            // bytes used in args[]
	__u32 args_count;
	__u8  args_truncated;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// pid -> last exec'd filename, used to best-effort resolve ParentImage.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, char[MAX_FILENAME_LEN]);
} pid_image_cache SEC(".maps");

// Matches the kernel's tracepoint/syscalls/sys_enter_execve format:
// args[0] = const char *filename, args[1] = const char *const *argv.
struct trace_event_raw_sys_enter_execve {
	unsigned long long unused;
	long syscall_nr;
	unsigned long args[6];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter_execve *ctx)
{
	struct exec_event *ev;
	struct task_struct *task;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->pid = pid;

	__u64 uid_gid = bpf_get_current_uid_gid();
	ev->uid = (__u32)uid_gid;
	ev->gid = (__u32)(uid_gid >> 32);

	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	task = (struct task_struct *)bpf_get_current_task();
	ev->ppid = BPF_CORE_READ(task, real_parent, tgid);

	const char *filename_ptr = (const char *)ctx->args[0];
	if (bpf_probe_read_user_str(&ev->filename, sizeof(ev->filename), filename_ptr) < 0)
		ev->filename[0] = 0;

	char *cached = bpf_map_lookup_elem(&pid_image_cache, &ev->ppid);
	if (cached)
		__builtin_memcpy(ev->parent_filename, cached, sizeof(ev->parent_filename));
	else
		ev->parent_filename[0] = 0;

	bpf_map_update_elem(&pid_image_cache, &pid, &ev->filename, BPF_ANY);

	const char *const *argv = (const char *const *)ctx->args[1];
	__u32 off = 0;
	__u32 count = 0;
	__u8 truncated = 0;

	#pragma unroll
	for (int i = 0; i < MAXARG; i++) {
		const char *argp = NULL;

		bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
		if (!argp)
			break;
		if (off + ARGSIZE > sizeof(ev->args)) {
			truncated = 1;
			break;
		}
		long n = bpf_probe_read_user_str(&ev->args[off], ARGSIZE, argp);
		if (n <= 0)
			break;
		off += n;
		count++;
	}
	ev->args_size = off;
	ev->args_count = count;
	ev->args_truncated = truncated;

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
