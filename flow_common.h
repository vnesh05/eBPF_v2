#ifndef FLOW_COMMON_H
#define FLOW_COMMON_H

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

struct flow_features {
    __u32 pkt_len_max;
    __u32 pkt_len_min;
    __u64 iat_max;
    __u64 last_seen;
    __u32 header_len_total;
    __u32 total_packets;
};

#endif
