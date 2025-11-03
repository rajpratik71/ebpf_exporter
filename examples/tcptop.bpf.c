#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"

#define MAX_ENTRIES 8192
#define TASK_COMM_LEN 16

#define AF_INET 2

struct key_t {
    u32 laddr;
    u32 raddr;
    u16 lport;
    u16 rport;
    u32 pid;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct key_t);
    __type(value, u64);
} tcptop_tx_bytes_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct key_t);
    __type(value, u64);
} tcptop_rx_bytes_total SEC(".maps");

static inline u16 read_dport(const struct sock *sk)
{
    return __builtin_bswap16(sk->__sk_common.skc_dport);
}

static int trace_ipv4_tx(const struct sock *sk, u64 bytes)
{
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }

    struct key_t key = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);

    key.laddr = sk->__sk_common.skc_rcv_saddr;
    key.raddr = sk->__sk_common.skc_daddr;
    key.lport = sk->__sk_common.skc_num;
    key.rport = read_dport(sk);
    key.pid = pid;
    bpf_get_current_comm(&key.comm, TASK_COMM_LEN);

    increment_map(&tcptop_tx_bytes_total, &key, bytes);

    return 0;
}

static int trace_ipv4_rx(const struct sock *sk, u64 bytes)
{
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }

    struct key_t key = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);

    key.laddr = sk->__sk_common.skc_rcv_saddr;
    key.raddr = sk->__sk_common.skc_daddr;
    key.lport = sk->__sk_common.skc_num;
    key.rport = read_dport(sk);
    key.pid = pid;
    bpf_get_current_comm(&key.comm, TASK_COMM_LEN);

    increment_map(&tcptop_rx_bytes_total, &key, bytes);

    return 0;
}

// Hook tcp_sendmsg to account for bytes handed to TCP send path.
// The prototype varies across kernels; we attempt a common match that
// should work for many kernels. If the verifier rejects this on some
// older/newer kernels, consider replacing with kprobe-based attach.
SEC("fentry/tcp_sendmsg")
int BPF_PROG(tcptop_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    u64 bytes = (u64)size;

    return trace_ipv4_tx(sk, bytes);
}

// Hook tcp_recvmsg to account for bytes received by TCP.
SEC("fentry/tcp_recvmsg")
int BPF_PROG(tcptop_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t size, int flags, int noblock)
{
    // The return value from recvmsg (bytes actually read) isn't available here
    // easily at fentry; we conservatively use the requested size as an approximation.
    u64 bytes = (u64)size;

    return trace_ipv4_rx(sk, bytes);
}

char LICENSE[] SEC("license") = "GPL";
