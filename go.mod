module github.com/chrisohaver/ebpf

go 1.16

require (
	github.com/cilium/ebpf v0.6.0
	github.com/coredns/caddy v1.1.0
	github.com/coredns/coredns v1.8.4
)

replace github.com/coredns/coredns v1.8.4 => ../../coredns/coredns
