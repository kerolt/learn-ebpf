//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

// 定义一个 eBPF ringbuf map，用于在内核空间和用户空间之间高效传递事件数据。
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __type(value, struct event);
} events SEC(".maps");

// 用于捕获和传递 TCP 连接事件的关键信息，通常在 eBPF 程序监控网络活动时使用。
// 当程序检测到新的 TCP连接时，会将连接的详细信息打包到这个结构体中，然后发送给用户空间程序进行处理。
struct event {
    u8 comm[16];
    __u16 sport;
    __be16 dport;
    __be32 saddr;
    __be32 daddr;
};

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock* sk) {
    if (sk->__sk_common.skc_family != AF_INET) {
        return 0;
    }

    struct event* tcp_info;
    tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!tcp_info) {
        return 0;
    }

    tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
    tcp_info->daddr = sk->__sk_common.skc_daddr;
    tcp_info->dport = sk->__sk_common.skc_dport;
    tcp_info->sport = bpf_htons(sk->__sk_common.skc_num);

    bpf_get_current_comm(&tcp_info->comm, TASK_COMM_LEN);

    bpf_ringbuf_submit(tcp_info, 0);

    return 0;
}