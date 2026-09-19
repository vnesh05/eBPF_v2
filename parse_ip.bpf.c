#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "flow_common.h"
#include "tree_params.h"

#define ETH_P_IP 0x0800
#define IPPROTO_TCP_LOCAL 6
#define FLOW_TIMEOUT_NS 60000000000ULL  // 60 seconds, in nanoseconds


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct flow_key);
    __type(value, struct flow_features);
} flow_map SEC(".maps");

#define MAX_TREE_DEPTH 16

static __always_inline int predict(int f[6])
{
    int node = 0;

    #pragma unroll
    for (int i = 0; i < MAX_TREE_DEPTH; i++) {
        if (tree_left[node] == -1)
            break;

        int feat_idx = tree_feature[node];
        int val = f[feat_idx];

        if (val <= tree_threshold[node])
            node = tree_left[node];
        else
            node = tree_right[node];
    }

    return tree_prediction[node];
}

SEC("xdp")
int xdp_flow_track(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP_LOCAL)
        return XDP_PASS;

    __u32 ip_hdr_len = ip->ihl * 4;
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;

    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.src_port = tcp->source;
    key.dst_port = tcp->dest;
    key.protocol = ip->protocol;

    __u32 pkt_len = bpf_ntohs(ip->tot_len);
    __u32 tcp_hdr_len = tcp->doff * 4;
    __u32 hdr_len = ip_hdr_len + tcp_hdr_len;
    __u64 now = bpf_ktime_get_ns();

    struct flow_features *feat = bpf_map_lookup_elem(&flow_map, &key);

    if (feat && (now - feat->last_seen) > FLOW_TIMEOUT_NS) {
        // Flow went quiet for too long — treat as a fresh flow instead
        // of continuing to accumulate stale stats
        feat->pkt_len_max = pkt_len;
        feat->pkt_len_min = pkt_len;
        feat->iat_max = 0;
        feat->last_seen = now;
        feat->header_len_total = hdr_len;
        feat->total_packets = 1;
        bpf_printk("Flow reset (was stale)\n");
    } else if (feat) {
        if (pkt_len > feat->pkt_len_max)
            feat->pkt_len_max = pkt_len;
        if (pkt_len < feat->pkt_len_min)
            feat->pkt_len_min = pkt_len;

        __u64 iat = now - feat->last_seen;
        if (iat > feat->iat_max)
            feat->iat_max = iat;

        feat->last_seen = now;
        feat->header_len_total += hdr_len;
        feat->total_packets += 1;

        bpf_printk("Flow update: pkts=%d max_len=%d\n", feat->total_packets, feat->pkt_len_max);
        
        int features[6];
        features[0] = bpf_ntohs(key.dst_port);
        features[1] = feat->pkt_len_max;
        features[2] = feat->pkt_len_min;
        features[3] = (int)(feat->iat_max / 1000);  // <-- THIS is the ns→µs fix
        features[4] = feat->header_len_total;
        features[5] = feat->total_packets;

        int result = predict(features);

        if (result == 1) {
            bpf_printk("ALERT: possible attack, dst_port=%d pkts=%d\n",
                       features[0], features[5]);
        }
    } else {
        struct flow_features new_feat = {};
        new_feat.pkt_len_max = pkt_len;
        new_feat.pkt_len_min = pkt_len;
        new_feat.iat_max = 0;
        new_feat.last_seen = now;
        new_feat.header_len_total = hdr_len;
        new_feat.total_packets = 1;
        bpf_map_update_elem(&flow_map, &key, &new_feat, BPF_ANY);
        bpf_printk("New flow started, dst_port=%d\n", bpf_ntohs(key.dst_port));

        int features[6];
        features[0] = bpf_ntohs(key.dst_port);
        features[1] = new_feat.pkt_len_max;
        features[2] = new_feat.pkt_len_min;
        features[3] = 0;  // no IAT yet on the very first packet
        features[4] = new_feat.header_len_total;
        features[5] = new_feat.total_packets;

        int result = predict(features);

        bpf_printk("DEBUG new: dst_port=%d len_max=%d\n", features[0], features[1]);
        bpf_printk("DEBUG new: pkts=%d result=%d\n", features[5], result);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
