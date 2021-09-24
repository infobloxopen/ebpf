# ebpf

## Name

*ebpf* - attach an eBPF XDP program to a specified interface.

## Description

This plugin allows you to use an eBPF XDP program to analyze and filter traffic before it reaches CoreDNS.
When CoreDNS exits, the program will be detached from the interface.

## Syntax

~~~ txt
ebpf {
  elf PROGRAM
  if INTERFACE
  map KEY VALUE
}
~~~

* `elf` **PROGRAM** - the ELF program to attach.  Se notes below on program requirements.
* `if` **INTERFACE** - the interface to attach to
* `map` **KEY** **VALUE** - the hexidecimal string representation of the **KEY** **VALUE** of
  an entry to load into the eBPF map. The `map` option may be specified more than once to add multiple
  items to the map.
  
## eBPF Program and Map Requirements

The program must be an XDP program, and main function named `xdp_prog`.
The map must be named `xdp_map`.

## Examples

If `my_xdp_program.o` defines a map with a 4 byte key, and the following struct as a value ...
```
struct maprec {
  __be32  ip4net;  // ipv4 network
  __be32  ip4mask; // ipv4 mask
};
```

The following will attach `my_xdp_program.o` to `eth0`, and load data for IP network `10.11.0.0` and
mask `255.255.0.0` (`0A0B0000` and `FFFF00000` respectively) into key `00000000` of the map. 

```
. {
  ebpf {
    if eth0
    elf my_xdp_program.o
    map 00000000 0A0B0000FFFF00000
  }
}
```

Enable debug to monitor map values and log when they change.

```
. {
  debug
  ebpf {
    if eth0
    elf my_xdp_program.o
    map 00000000 000000020A0B0000FFFF00000
  }
}
```

