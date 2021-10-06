#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"

#define MAP_MAX_RECS 128

#define ACTION_BLOCK 1
#define ACTION_ALLOW 2

struct maprec {
	__be32  action;  // action block:1 allow:2
        __be32  ip4net;  // ipv4 network
        __be32  ip4mask; // ipv4 mask
        struct in6_addr ip6net;  // ipv6 network
        struct in6_addr ip6mask; // ipv6 mask
};

struct bpf_map_def SEC("maps") xdp_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct maprec),
	.max_entries = MAP_MAX_RECS,
};

static __always_inline int check_addr(__be32 v4saddr, struct in6_addr *v6saddr){
	struct maprec *subnet;
	__u32 key;
	__be32 action = ACTION_ALLOW;

	// get map record that matches source address
	#pragma unroll
	for (__u32 i = 0; i < MAP_MAX_RECS; i++) {	
		key = i;
        	subnet = bpf_map_lookup_elem(&xdp_map, &key);
		if (!subnet)
			return XDP_PASS; // reached end of list without finding a match

		if (!subnet->action)
			return XDP_PASS; // reached last entry without finding a match

		if (v4saddr) {
			if (!subnet->ip4net) {
				// if an ipv6 mask is defined this is not a default action, try next record
				if ((subnet->ip6mask.in6_u.u6_addr16[0] & 1)) // a valid non-zero mask will always have a 1 in most significant bit
					continue; 
				// else both ip4 and ip6 masks are zero, this is a default action, which matches all IPs
				goto dfault;
			}

			if ((v4saddr & subnet->ip4mask) != subnet->ip4net) {

				continue; // ip source not in this subnet, try next record
			}

		} else if (v6saddr) {
			if (!(subnet->ip6mask.in6_u.u6_addr16[0] & 1)) { // a valid non-zero mask will always have a 1 in most significant bit
				// if an ipv4 mask is defined this is not a default action, try next record
				if (subnet->ip4mask) { 
					continue; // ipv6 mask is invalid/empty, try next record
				}
				// else both ip6 and ip4 masks are zero, this is a default action, which matches all IPs
				goto dfault;
			}
	
			#pragma unroll
			for (int j = 0; j < 4; j++) {
				if ((v6saddr->in6_u.u6_addr32[j] & subnet->ip6mask.in6_u.u6_addr32[j]) != subnet->ip6net.in6_u.u6_addr32[j])
					goto nextrec;
			}
		}

		dfault:
		action = bpf_ntohl(subnet->action);
		break;
		nextrec:;
	}

	if (action == ACTION_ALLOW){
		return XDP_PASS;
	}

	if (action == ACTION_BLOCK)
		return XDP_DROP;

	return XDP_PASS;
}

SEC("xdp")
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
		return check_addr(ip4_saddr, 0);
	}
	return check_addr(0, &ip6_saddr);
}

char _license[] SEC("license") = "GPL";

