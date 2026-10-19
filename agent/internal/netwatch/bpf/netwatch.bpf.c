// netwatch.bpf.c — network telemetry for the SIEM agent.
//
// Attaches tracepoints for the syscalls that open or name a connection:
//   sys_enter_connect   outbound dial
//   sys_enter_bind      listener / listener port change
//   sys_enter_accept4   inbound accept (accept goes through accept4 on modern libcs)
//   sys_enter_sendto    UDP send; only kept when the peer port is 53 (DNS query)
//
// One ringbuf record type carries every event; the syscall field tells the Go
// loader which log type to emit. Addresses are read from the sockaddr the
// caller passed, so the event describes what the process asked for, not what
// the kernel later did to it.
#include "procexec/bpf/include/bpf/vmlinux.h"
#include "procexec/bpf/include/bpf/bpf_helpers.h"
#include "procexec/bpf/include/bpf/bpf_tracing.h"
#include "procexec/bpf/include/bpf/bpf_core_read.h"
#include "procexec/bpf/include/bpf/bpf_endian.h"

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAX_HOST_LEN  128

#define AF_INET_  2
#define AF_INET6_ 10

#define SYSCALL_CONNECT 1
#define SYSCALL_BIND    2
#define SYSCALL_ACCEPT  3
#define SYSCALL_DNS     4

struct net_event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 gid;
	__u8  syscall_kind;
	__u8  family;
	__u8  proto;
	__u8  pad;
	__u16 local_port;
	__u16 remote_port;
	__u32 saddr_v4;
	__u32 daddr_v4;
	char  comm[TASK_COMM_LEN];
	char  host[MAX_HOST_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} net_events SEC(".maps");

static __always_inline void fill_identity(struct net_event *ev)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	ev->timestamp_ns = bpf_ktime_get_ns();
	ev->tgid = pid_tgid >> 32;
	ev->pid = pid_tgid;
	ev->uid = (__u32)uid_gid;
	ev->gid = (__u32)(uid_gid >> 32);
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
}

// Copies an IPv4 sockaddr (sin_family, sin_port, sin_addr) into the event.
static __always_inline int read_sockaddr(struct net_event *ev, void *uaddr)
{
	struct sockaddr_in sa = {};

	if (!uaddr)
		return -1;
	if (bpf_probe_read_user(&sa, sizeof(sa), uaddr) < 0)
		return -1;
	if (sa.sin_family != AF_INET_)
		return -1;

	ev->family = sa.sin_family;
	ev->remote_port = bpf_ntohs(sa.sin_port);
	ev->daddr_v4 = sa.sin_addr.s_addr;
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct net_event *ev;

	ev = bpf_ringbuf_reserve(&net_events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	fill_identity(ev);
	ev->syscall_kind = SYSCALL_CONNECT;
	ev->proto = 6;

	if (read_sockaddr(ev, (void *)ctx->args[1]) < 0) {
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int handle_bind(struct trace_event_raw_sys_enter *ctx)
{
	struct net_event *ev;

	ev = bpf_ringbuf_reserve(&net_events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	fill_identity(ev);
	ev->syscall_kind = SYSCALL_BIND;

	if (read_sockaddr(ev, (void *)ctx->args[1]) < 0) {
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}

	ev->local_port = ev->remote_port;
	ev->remote_port = 0;
	bpf_ringbuf_submit(ev, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int handle_accept(struct trace_event_raw_sys_enter *ctx)
{
	struct net_event *ev;

	ev = bpf_ringbuf_reserve(&net_events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	fill_identity(ev);
	ev->syscall_kind = SYSCALL_ACCEPT;
	ev->proto = 6;

	if (read_sockaddr(ev, (void *)ctx->args[1]) < 0) {
		bpf_ringbuf_discard(ev, 0);
		return 0;
	}

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

// UDP sendto: args[0]=fd, args[1]=buf, args[2]=len, args[3]=flags,
// args[4]=struct sockaddr *, args[5]=addrlen. Only port 53 is kept, which is
// the process-visible half of a DNS query (the name is copied from the buffer).
SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter *ctx)
{
	struct net_event *ev;
	void *ubuf = (void *)ctx->args[1];
	__u32 len = (__u32)ctx->args[2];
	struct sockaddr_in sa = {};
	char scratch[64] = {};

	if (!ubuf || !(void *)ctx->args[4])
		return 0;

	if (bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[4]) < 0)
		return 0;
	if (sa.sin_family != AF_INET_ || bpf_ntohs(sa.sin_port) != 53)
		return 0;

	ev = bpf_ringbuf_reserve(&net_events, sizeof(*ev), 0);
	if (!ev)
		return 0;

	fill_identity(ev);
	ev->syscall_kind = SYSCALL_DNS;
	ev->proto = 17;
	ev->family = sa.sin_family;
	ev->remote_port = 53;
	ev->daddr_v4 = sa.sin_addr.s_addr;

	// DNS question name starts at byte 12. Best-effort: stop at the first
	// length byte of 0 or anything outside the printable range, so a
	// malformed packet simply yields a short/empty host.
	if (len > 12) {
		__u32 copy = len - 12;
		if (copy > MAX_HOST_LEN - 1)
			copy = MAX_HOST_LEN - 1;
		if (bpf_probe_read_user(scratch, sizeof(scratch), (char *)ubuf + 12) == 0) {
			__u32 i = 0;
			__u32 out = 0;
#pragma unroll
			for (i = 0; i < 64; i++) {
				__u8 c = (__u8)scratch[i];
				if (c == 0)
					break;
				if (c < 32 || c > 126) {
					// length prefix: replace with a dot separator
					if (out > 0 && out < MAX_HOST_LEN - 1)
						ev->host[out++] = '.';
					continue;
				}
				if (out < MAX_HOST_LEN - 1)
					ev->host[out++] = c;
			}
		}
	}

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
