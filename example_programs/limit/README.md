# limit

This example implements a packet rate limiter.  It tracks the number of packets received per each
configured subnet, and if the number of packets received in one second exceed the per second allowance for
the corresponding subnet, the program drops packets before they reach CoreDNS until the next second.
eBPF XDP programs only receive ingress packets, so these limits do not apply to egress traffic on the same interface.

The map record structure is as follows
```
struct maprec {
        __be32 limit; // packets allowed per second

        __be32  ip4net;  // ipv4 network
        __be32  ip4mask; // ipv4 mask

        struct in6_addr ip6net;  // ipv6 network
        struct in6_addr ip6mask; // ipv6 mask

        __u64 pkt_count;
        __u64 next_interval;
};
```

A `limit` of zero signifies an empty map array entry. If the program reaches an empty map entry or the real end of the
map before finding a source ip subnet match, it will allow the packet to pass through.

## Example

Define two subnets, `10.11.0.0/16` with a limit of 1000 packets per second, and `FC00:DEAD:CAFE:1::0/64` with a limit
of 2000 packets per second.

```
  ebpf {
    if eth0
    elf xdp_limit_prog_kern.o
    
    # Fields denoted here for easier readability
    #   limit    4net     4msk     6net                             6msk                             pkt-count        next-interval    padding - see Bugs
    map 000003E8.0A0B0000.FFFF0000.00000000000000000000000000000000.00000000000000000000000000000000.0000000000000000.0000000000000000.00000000
    map 000007D0.00000000.00000000.FC00DEADCAFE00010000000000000000.FFFFFFFFFFFFFFFF0000000000000000.0000000000000000.0000000000000000.00000000
  }
```

## Limitations

Raw _packets_ are counted, not DNS requests. TCP transactions use more packets per DNS request (e.g. syn/ack handshaking),
and therefore will exhaust a per packet limit faster than UDP transactions which generally use one packet per request.
One work around would be to exclude TCP packets with certain flags combos from incrementing the packet count. Another way
to address this would be to parse the packets down to application, and only increment the packet count for actual DNS
requests.

## Bugs

For some reason unknown to me, the map loader expects a map value length of 64 bytes, when the actual structure
length is 60 bytes. Therefore, each map entry must be padded with 8 additional zeros (4 bytes) to satisfy the map loader.