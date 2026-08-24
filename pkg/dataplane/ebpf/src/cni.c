// SPDX-License-Identifier: GPL-2.0
// Coordino CNI eBPF programs for tc ingress/egress hooks
//
// These programs implement identity-based policy enforcement:
// 1. Look up source/destination pod IP in identity map → get identity ID
// 2. Look up (src_identity, dst_identity) in policy map → get verdict
// 3. Allow or drop packet based on verdict

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct policy_key {
    __u32 src_id;
    __u32 dst_id;
    __u8 proto;
    __u16 port;
};

struct policy_value {
    __u8 verdict;
    __u8 audit;
};

struct endpoint_info {
    __u32 ifindex;
    __u32 identity;
    __u8 mac[6];
};

struct flow_event {
    __u32 src_id;
    __u32 dst_id;
    __u8 proto;
    __u16 port;
    __u8 verdict;
    __u8 policy_match;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} identity_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct policy_key);
    __type(value, struct policy_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct endpoint_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} endpoint_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} conntrack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

static __always_inline int handle_pkt(struct __sk_buff *skb, bool ingress) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 proto = ip->protocol;
    __u16 dport = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        dport = bpf_ntohs(tcp->dest);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        dport = bpf_ntohs(udp->dest);
    }

    __u32 *src_id = bpf_map_lookup_elem(&identity_map, &src_ip);
    __u32 *dst_id = bpf_map_lookup_elem(&identity_map, &dst_ip);

    __u32 s_id = src_id ? *src_id : 0;
    __u32 d_id = dst_id ? *dst_id : 0;

    struct policy_key key = {
        .src_id = s_id,
        .dst_id = d_id,
        .proto = proto,
        .port = dport,
    };

    struct policy_value *val = bpf_map_lookup_elem(&policy_map, &key);
    __u8 verdict = 1; // Default allow
    __u8 policy_match = 0;
    
    if (val) {
        verdict = val->verdict;
        policy_match = 1;
    }

    struct flow_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->src_id = s_id;
        event->dst_id = d_id;
        event->proto = proto;
        event->port = dport;
        event->verdict = verdict;
        event->policy_match = policy_match;
        bpf_ringbuf_submit(event, 0);
    }

    if (verdict == 0)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

SEC("tc")
int cni_tc_ingress(struct __sk_buff *skb) {
    return handle_pkt(skb, true);
}

SEC("tc")
int cni_tc_egress(struct __sk_buff *skb) {
    return handle_pkt(skb, false);
}
