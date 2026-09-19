#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_hello(struct xdp_md *ctx)
{
    bpf_printk("Got a packet!\n");
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
