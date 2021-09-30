package ebpf

import (
	"encoding/hex"
	"reflect"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("ebpf")

func init() { plugin.Register("ebpf", setup) }

func setup(c *caddy.Controller) error {

	type mapValue struct {
		key   []byte
		value []byte
	}

	var elfName string
	var ifName string
	var mapValues []mapValue

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "elf":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				elfName = args[0]
			case "if":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return c.ArgErr()
				}
				ifName = args[0]
			case "map":
				args := c.RemainingArgs()
				if len(args) != 2 {
					return c.ArgErr()
				}
				key, err := hex.DecodeString(args[0])

				if err != nil {
					return c.Errf("Map key '%v' must be a hexadecimal string", args[0])
				}
				val, err := hex.DecodeString(args[1])
				if err != nil {
					return c.Errf("Map value '%v' must be a hexadecimal string", args[1])
				}
				mapValues = append(mapValues, mapValue{key, val})
			default:
				return c.Errf("Unknown option '%v'", c.Val())
			}
		}
	}

	if elfName == "" {
		return c.Err("`elf` required")
	}
	if ifName == "" {
		return c.Err("`if` required")
	}

	detatchFn, p, m, err := AttachXDP(elfName, ifName)
	if err != nil {
		panic(err)
	}

	// set map values
	for i := range mapValues {
		if err := m.Update(mapValues[i].key, mapValues[i].value, 0); err != nil {
			return err
		}
	}

	config := dnsserver.GetConfig(c)
	if config.Debug {
		// poll map values for changes
		go func() {
			// todo: add stop channel
			// todo: defer this to onstartup
			// todo: this essentially assumes an array map, make it also work with hash maps.
			prev := make(map[int][]byte)
			for {
				var key, val []byte
				i := m.Iterate()
				n := 0
				for i.Next(&key, &val) {
					if !reflect.DeepEqual(prev[n], val) {
						log.Debugf("poll map(n=%v): val=%v", n, val)
						valc := make([]byte, len(val))
						copy(valc, val)
						prev[n] = valc
					}
					n++
				}
				time.Sleep(time.Millisecond * 100)

			}
		}()
	}

	c.OnShutdown(func() error {
		// close the sock, program and map on shutdown
		//sErr := syscall.Close(sock)
		var dErr, pErr, mErr error
		if p != nil {
			pErr = p.Close()
		}
		if m != nil {
			mErr = m.Close()
		}
		if detatchFn != nil {
			dErr = detatchFn()
		}
		if dErr != nil {
			return dErr
		}
		if pErr != nil {
			return pErr
		}
		return mErr
	})

	return nil
}
