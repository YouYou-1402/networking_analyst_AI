// src/core/layer1/xdp_filter.bpf.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ==================== BPF Maps ====================

// IP Blacklist Map (Hash Map)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);  // 1M entries
    __type(key, __u32);            // IP address (network byte order)
    __type(value, __u32);          // 1 = blacklisted
} ip_blacklist SEC(".maps");

// Statistics Map
struct xdp_stats {
    __u64 total_packets;
    __u64 passed_packets;
    __u64 dropped_packets;
    __u64 blacklist_hits;
    __u64 rate_limit_hits;
    __u64 malformed_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_stats);
} xdp_stats SEC(".maps");

// Configuration Map
struct xdp_config {
    __u32 rate_limit_pps;
    __u32 enable_rate_limiting;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_config);
} xdp_config SEC(".maps");

// ==================== Helper Functions ====================

static __always_inline void update_stats(__u32 stat_type)
{
    __u32 key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&xdp_stats, &key);
    
    if (!stats)
        return;
    
    __sync_fetch_and_add(&stats->total_packets, 1);
    
    switch (stat_type)
    {
        case XDP_PASS:
            __sync_fetch_and_add(&stats->passed_packets, 1);
            break;
        case XDP_DROP:
            __sync_fetch_and_add(&stats->dropped_packets, 1);
            break;
        case 10: // Blacklist hit
            __sync_fetch_and_add(&stats->blacklist_hits, 1);
            break;
        case 11: // Rate limit hit
            __sync_fetch_and_add(&stats->rate_limit_hits, 1);
            break;
        case 12: // Malformed packet
            __sync_fetch_and_add(&stats->malformed_packets, 1);
            break;
    }
}

static __always_inline int check_ip_blacklist(__u32 src_ip)
{
    __u32 *value = bpf_map_lookup_elem(&ip_blacklist, &src_ip);
    
    if (value && *value == 1)
    {
        update_stats(10); // Blacklist hit
        return 1; // Blacklisted
    }
    
    return 0; // Not blacklisted
}

// ==================== Main XDP Program ====================

SEC("xdp")
int xdp_filter_main(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        update_stats(12); // Malformed packet
        return XDP_DROP;
    }
    
    // Check if IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        update_stats(XDP_PASS);
        return XDP_PASS; // Not IPv4, pass through
    }
    
    // Parse IP header
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
    {
        update_stats(12); // Malformed packet
        return XDP_DROP;
    }
    
    // Extract source IP
    __u32 src_ip = iph->saddr;
    
    // Check IP blacklist
    if (check_ip_blacklist(src_ip))
    {
        update_stats(XDP_DROP);
        return XDP_DROP; // Drop blacklisted IP
    }
    
    // TODO: Add rate limiting logic here
    
    // Pass packet
    update_stats(XDP_PASS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
