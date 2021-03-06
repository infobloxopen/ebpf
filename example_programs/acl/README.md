# acl

This example implements a simple access control list.  The program map is an array representing the access control list,
each map element containing source CIDRs and an action. Each element of the array is evaluated in order for every incoming
packet until a match is found.  If no CIDRs match the source IP, the packet is allowed.

The map record structure is as follows...
```cgo
struct maprec { 
        __be32  action;  // action block:1 allow:2
        __be32  ip4net;  // ipv4 network
        __be32  ip4mask; // ipv4 mask
        struct in6_addr ip6net;  // ipv6 network
        struct in6_addr ip6mask; // ipv6 mask
};
```

## Example

Allow two subnets`10.11.0.0/16` and `FC00:DEAD:CAFE:1::0/64`, block all others.

```
  ebpf {
    if eth0
    elf xdp_prog_kern.o

    #   action   4net     4msk     6net                             6msk                             count
    map 00000002.0A0B0000.FFFF0000.00000000000000000000000000000000.00000000000000000000000000000000.00000000
    map 00000002.00000000.00000000.FC00DEADCAFE00010000000000000000.FFFFFFFFFFFFFFFF0000000000000000.00000000
    map 00000001.00000000.00000000.00000000000000000000000000000000.00000000000000000000000000000000.00000000
  }
```

Register metrics for the packet count of each acl rule.

```
  ebpf {
    if eth0
    elf xdp_prog_kern.o

    #   action   4net     4msk     6net                             6msk                             count
    map 00000002.0A0B0000.FFFF0000.00000000000000000000000000000000.00000000000000000000000000000000.00000000
    map 00000002.00000000.00000000.FC00DEADCAFE00010000000000000000.FFFFFFFFFFFFFFFF0000000000000000.00000000
    map 00000001.00000000.00000000.00000000000000000000000000000000.00000000000000000000000000000000.00000000
    
    metric packets_allowed_subnet_a_total 00000000 44 4 "Total packets allowed from subnet A."
    metric packets_allowed_subnet_b_total 01000000 44 4 "Total packets allowed from subnet B."
    metric packets_blocked_total 02000000 44 4 "Total packets blocked."

  }
```