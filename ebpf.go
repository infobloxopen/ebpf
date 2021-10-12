package ebpf

import (
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var log = clog.NewWithPlugin("ebpf")

func init() { plugin.Register("ebpf", setup) }

func setup(c *caddy.Controller) error {

	type mapValue struct {
		key   []byte
		value []byte
	}

	type metric struct {
		gauge    prometheus.Gauge
		lastVal  uint64
		key      []byte
		pos, len int
	}

	var elfName string
	var ifName string
	var mapValues []mapValue
	var metrics []*metric

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
				if len(args) < 1 || len(args) > 3 {
					return c.ArgErr()
				}
				if len(args) == 2 {
					key, err := hex.DecodeString(args[0])
					if err != nil {
						return c.Errf("Map key '%v' must be a hexadecimal", args[0])
					}
					val, err := parseMapValue(args[1])
					if err != nil {
						return err
					}
					mapValues = append(mapValues, mapValue{key, val})
					continue
				}

				val, err := parseMapValue(args[0])
				if err != nil {
					return err
				}
				mapValues = append(mapValues, mapValue{nil, val})
			case "metric":
				// metric NAME KEY POS LEN HELP
				args := c.RemainingArgs()
				key, err := hex.DecodeString(args[1])
				if err != nil {
					return c.Errf("metric KEY '%v' must be a hexadecimal", args[1])
				}
				pos, err := strconv.Atoi(args[2])
				if err != nil {
					return c.Errf("metric POS '%v' must be an integer", args[2])
				}
				length, err := strconv.Atoi(args[3])
				if err != nil {
					return c.Errf("metric LEN '%v' must be an integer number of bytes", args[3])
				}
				if length > 8 {
					return c.Errf("metric LEN '%v' must no greater than 8", args[3])
				}
				metrics = append(metrics, &metric{
					gauge: promauto.NewGauge(prometheus.GaugeOpts{
						Namespace: plugin.Namespace,
						Subsystem: "ebpf",
						Name:      args[0],
						Help:      args[4],
					}),
					key: key,
					pos: pos,
					len: length,
				})

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
		if mapValues[i].key == nil {
			// if key is not specified, use index as key (array map entry)
			err := m.Update(uint32(i), mapValues[i].value, 0)
			if err != nil {
				return err
			}
			continue
		}
		// if key is specified, use it as the key (hash map entry)
		err := m.Update(mapValues[i].key, mapValues[i].value, 0)
		if err != nil {
			return err
		}
	}

	if len(metrics) > 0 {
		// poll map values for metric updates
		go func() {
			// todo: add stop channel, move to onstartup/onshutdown events
			for {
				for _, metric := range metrics {
					var entry []byte
					var valbytes = make([]byte, 8)
					err := m.Lookup(metric.key, &entry)
					if err != nil {
						log.Errorf("Failed to look up metric: %v", err)
						continue
					}
					copy(valbytes, entry[metric.pos:metric.pos+metric.len])
					val := binary.LittleEndian.Uint64(valbytes)
					if val != metric.lastVal {
						metric.gauge.Set(float64(val))
						metric.lastVal = val
					}
				}
				time.Sleep(time.Millisecond * 100) // todo: make configurable?
			}
		}()
	}

	config := dnsserver.GetConfig(c)
	if config.Debug {
		// poll map values for changes
		go func() {
			// todo: add stop channel
			// todo: defer this to onstartup
			prev := make(map[int][]byte)
			for {
				var key, val []byte
				i := m.Iterate()
				n := 0
				for i.Next(&key, &val) {
					if !reflect.DeepEqual(prev[n], val) {
						log.Debugf("poll map: key=%v val=%v", key, val)
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

func parseMapValue(in string) ([]byte, error) {
	// strip out .'s, decode as hex
	val, err := hex.DecodeString(strings.Replace(in, ".", "", -1))
	if err != nil {
		return nil, errors.Errorf("Map value '%v' invalid format: %v", in, err)
	}
	return val, nil
}
