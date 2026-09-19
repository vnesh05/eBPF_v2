#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include "flow_common.h"

#define FLOW_TIMEOUT_NS 60000000000ULL

static __u64 now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(void)
{
    int map_fd = bpf_obj_get("/sys/fs/bpf/parse_ip_maps/flow_map");
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    printf("Connected to flow_map. Polling every 5 seconds...\n\n");

    while (1) {
        struct flow_key key = {}, next_key;
        int flow_count = 0, deleted_count = 0;
        __u64 t = now_ns();

        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            struct flow_features feat;

            if (bpf_map_lookup_elem(map_fd, &next_key, &feat) == 0) {
                if ((t - feat.last_seen) > FLOW_TIMEOUT_NS) {
                    bpf_map_delete_elem(map_fd, &next_key);
                    deleted_count++;
                } else {
                    printf("Flow dst_port=%-6d pkts=%-4d max_len=%-5d min_len=%-5d iat_max_ns=%llu\n",
                           __builtin_bswap16(next_key.dst_port),
                           feat.total_packets, feat.pkt_len_max,
                           feat.pkt_len_min, feat.iat_max);
                    flow_count++;
                }
            }

            key = next_key;
        }

        printf("-- %d active flows, %d stale flows swept --\n\n", flow_count, deleted_count);
        sleep(5);
    }

    return 0;
}
