#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"

#define MAP_MAX_RECS 16

struct maprec {
        __be32 limit; // packets allowed per interval

        __be32  ip4net;  // ipv4 network
        __be32  ip4mask; // ipv4 mask

        struct in6_addr ip6net;  // ipv6 network
        struct in6_addr ip6mask; // ipv6 mask

        __u64 pkt_count;
        __u64 next_interval;
};

struct bpf_map_def SEC("maps") xdp_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct maprec),
	.max_entries = MAP_MAX_RECS,
};

static __always_inline __be16 limit_packet(__be32 v4saddr, struct in6_addr *v6saddr){
	struct maprec *subnet;
	__u32 key;
	int found = 0;

	// get map record that matches source address
	#pragma unroll
	for (int i = 0; i < MAP_MAX_RECS; i++) {	
		key = i;
        	subnet = bpf_map_lookup_elem(&xdp_map, &key);
		if (!subnet)
			return XDP_PASS; // reached end of list without finding a match
		if (v4saddr) {
			if (!subnet->ip4net) 
				continue; // no ipv4 network defined, try next record

			if ((v4saddr & subnet->ip4mask) != subnet->ip4net)
				continue; // ip source not in this subnet, try next record
		}

		if (v6saddr) {
			if (!(subnet->ip6mask.in6_u.u6_addr16[0] & 1)) // a valid non-zero mask will always have a 1 in most significant bit
				continue; // ipv6 mask is invalid/empty, try next record
	
			#pragma unroll
			for (int j = 0; j < 4; j++) {
				if ((v6saddr->in6_u.u6_addr32[j] & subnet->ip6mask.in6_u.u6_addr32[j]) != subnet->ip6net.in6_u.u6_addr32[j])
					goto nextrec;
			}
		}

		found = 1;
		break;
		nextrec:;
	}

	if (!found)
		return XDP_PASS;

	// check to see if we have reached the next interval
	__u64 now = bpf_ktime_get_ns();
	if (now > subnet->next_interval) {
		subnet->next_interval = now + 1000000000;  // 1 billion ns = 1s. todo: make configurable. store value in maprec?
		subnet->pkt_count = 1;
		return XDP_PASS;
	}

	// incrememt packet count
	__sync_fetch_and_add(&subnet->pkt_count, 1); 


	// if packet count limit is exceeded, drop the packet
	if (subnet->pkt_count > bpf_ntohl(subnet->limit)) {
		return XDP_DROP;
	}

	return XDP_PASS;
}

SEC("xdp_prog1")
int xdp_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	struct ipv6hdr *ip6h;
	struct iphdr *iph;

	__be32 ip4_saddr = 0;
	struct in6_addr ip6_saddr = { .in6_u.u6_addr32 = {0,0,0,0} };

	int ipv = 0;

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		ipv = 6;
		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (nh_type < 0)
			return XDP_PASS;

		ip6_saddr = ip6h->saddr;

	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		ipv = 4;
		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type < 0)
			return XDP_PASS;

		ip4_saddr = iph->saddr;

	} else {
		return XDP_PASS;
	}

	if (ipv == 4) {
		return limit_packet(ip4_saddr, 0);
	}
	return limit_packet(0, &ip6_saddr);
}

char _license[] SEC("license") = "GPL";

