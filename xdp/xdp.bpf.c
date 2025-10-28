//go:build ignore

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

// 检查以太网帧是否为 TCP 包
static __always_inline int is_tcp(struct ethhdr* eth, void* data_end) {
    if ((void*) (eth + 1) > data_end)
        return 0;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return 0;
    }

    struct iphdr* ip = (struct iphdr*) (eth + 1);
    if ((void*) (ip + 1) > data_end) {
        return 0;
    }

    return ip->protocol == IPPROTO_TCP;
}

SEC("xdp")
int xdp_pass(struct xdp_md* ctx) {
    void* data = (void*) (long) ctx->data;
    void* data_end = (void*) (long) ctx->data_end;

    struct ethhdr* eth = data;
    if (!is_tcp(eth, data_end)) {
        return XDP_PASS;
    }

    struct iphdr* ip = (struct iphdr*) (eth + 1);

    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }

    if ((void*) ip + ip_hdr_len > data_end) {
        return XDP_PASS;
    }

    struct tcphdr* tcp = (struct tcphdr*) ((void*) ip + ip_hdr_len);
    const int capture_byte_size = 32;

    // 确保不会读取超出数据结尾的数据
    if ((void*) tcp + capture_byte_size > data_end) {
        return XDP_PASS;
    }

    void* ringbuf_space = bpf_ringbuf_reserve(&rb, capture_byte_size, 0);
    if (!ringbuf_space) {
        return XDP_PASS;
    }

    // 将 TCP 头的前 32 字节写入 ring buffer
    for (int i = 0; i < capture_byte_size; i++) {
        ((unsigned char*) ringbuf_space)[i] = ((unsigned char*) tcp)[i];
    }

    bpf_ringbuf_submit(ringbuf_space, 0);

    bpf_printk("Captured TCP header (%d bytes)", capture_byte_size);

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";