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
