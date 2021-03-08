package epicmdns

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy/caddyfile"
	"github.com/epiclabs-io/epicmdns/mdns"
)

type config struct {
	Domain string
	mdns.Config
}

// parseConfig reads the CoreDNS file and returns the plug-in configuration
//	epicmdns epiclabs.io {
//		min_ttl 300                     # (int, seconds) minimum TTL to keep records for, overriding mDNS response. Default 300s
//		browse_period 60                # (int, seconds) period to keep service list updated. Default 60s
//		force_unicast                   # (bool) whether we ask hosts to respond directly to us if possible. Default false
//		ip4 1.2.3.4                     # (string, IP address) IPv4 interface to bind to. Defaults to 0.0.0.0
//		ip6 fe80::abc:cdef:0123:4567    # (string, IP address) IPv6 interface to bind to. Defaults to 0::0
//		browse _workstation._tcp.local  # (string) repeat as necessary. List of services to scan and keep updated
//		browse service1._tcp.local
//		browse_period  60               # (int, seconds) How often scan the list of services. Default 60s
//		retry_period 0.250              # (float, seconds) How often retry mDNS queries. Default 0.250s
//		cache_purge_period 300          # (int, seconds) How often clean the cache for stale records. Default 300s

func parseConfig(c *caddyfile.Dispenser) (*config, error) {
	var config config
	c.Next()
	if c.NextArg() {
		config.Domain = "." + strings.TrimSuffix(c.Val(), ".") + "."
		if c.NextBlock() {
			for {
				key := c.Val()
				c.NextArg()
				value := c.Val()
				switch key {
				case "force_unicast":
					config.ForceUnicastResponses = true
				case "ip4":
					ip := net.ParseIP(value)
					if len(ip) != len(net.IPv4zero) {
						return nil, errors.New("Cannot parse ip4 address")
					}
					config.BindIPAddressV4 = ip

				case "ip6":
					ip := net.ParseIP(value)
					if len(ip) != len(net.IPv6zero) {
						return nil, errors.New("Cannot parse ip6 address")
					}
					config.BindIPAddressV6 = ip

				case "min_ttl":
					minttl, err := strconv.ParseUint(value, 10, 32)
					if err != nil {
						return nil, errors.New("Cannot parse min_ttl")
					}
					config.MinTTL = uint32(minttl)
				case "browse":
					config.BrowseServices = append(config.BrowseServices, value)
				case "browse_period":
					period, err := strconv.ParseUint(value, 10, 32)
					if err != nil {
						return nil, errors.New("Cannot parse browse_period")
					}
					config.BrowsePeriod = time.Duration(period) * time.Second
				case "retry_period":
					period, err := strconv.ParseFloat(value, 32)
					if err != nil {
						return nil, errors.New("Cannot parse retry_period")
					}
					config.RetryPeriod = time.Duration(period*1000) * time.Millisecond
				case "cache_purge_period":
					period, err := strconv.ParseUint(value, 10, 32)
					if err != nil {
						return nil, errors.New("Cannot parse cache_period")
					}
					config.CachePurgePeriod = time.Duration(period) * time.Second

				}
				if !c.NextBlock() {
					break
				}
			}
		}
		return &config, nil
	}
	return nil, errors.New("config syntax error")
}
