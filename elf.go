package ebpf

import (
	"encoding/binary"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

func AttachXDP(fileName, ifName string) (detachFn func() error, prog *ebpf.Program, ebpfMap *ebpf.Map, err error){
	spec, err := ebpf.LoadCollectionSpec(fileName)
	if err != nil {
		return nil,nil, nil, err
	}

	var objs struct {
		Prog  *ebpf.Program `ebpf:"xdp_prog"`
		Map   *ebpf.Map     `ebpf:"xdp_map"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil,nil, nil, err
	}

	// todo: how to work around hard coded program name and map name req in spec.LoadAndAssign()?
	//       spec.LoadAndAssign() uses struct tags, which cannot be variable.
	//       Maybe we dont need to, just require that the program name and map name be fixed values in the ELF.
	//       kinda sucks, but may have to work that way.

	// XDP attach from https://networkop.co.uk/post/2021-03-ebpf-intro/
	link, err := netlink.LinkByName(ifName)
	err = netlink.LinkSetXdpFd(link, objs.Prog.FD())

	detachFn = func() error {
		return netlink.LinkSetXdpFd(link, -1)
	}

	return detachFn, objs.Prog, objs.Map, nil
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}