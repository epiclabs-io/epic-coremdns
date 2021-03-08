package mdns

import (
	"net"
	"time"

	"github.com/epiclabs-io/epicmdns/mdns/udptransport"
	"github.com/tilinna/clock"
)

type Config struct {
	ForceUnicastResponses bool
	BindIPAddressV4       net.IP
	BindIPAddressV6       net.IP
	MinTTL                uint32
	BrowseServices        []string
	BrowsePeriod          time.Duration
	CachePurgePeriod      time.Duration
	RetryPeriod           time.Duration
	Transport             transport
	Clock                 clock.Clock
}

var DefaultConfig = &Config{
	ForceUnicastResponses: false,
	MinTTL:                300,
	BrowsePeriod:          60 * time.Second,
	CachePurgePeriod:      300 * time.Second,
	RetryPeriod:           250 * time.Millisecond,
	Transport:             nil,
	Clock:                 clock.Realtime(),
	BindIPAddressV4:       net.IPv4zero,
	BindIPAddressV6:       net.IPv6zero,
}

func (config *Config) ApplyDefaults() error {
	if config.BindIPAddressV4 == nil {
		config.BindIPAddressV4 = DefaultConfig.BindIPAddressV4
	}
	if config.BindIPAddressV6 == nil {
		config.BindIPAddressV6 = DefaultConfig.BindIPAddressV6
	}
	if config.Transport == nil {
		transport, err := udptransport.New(&udptransport.Config{
			BindIPAddressV4: config.BindIPAddressV4,
			BindIPAddressV6: config.BindIPAddressV6,
		})
		if err != nil {
			return err
		}
		config.Transport = transport
	}
	if config.Clock == nil {
		config.Clock = DefaultConfig.Clock
	}
	if config.CachePurgePeriod == 0 {
		config.CachePurgePeriod = DefaultConfig.CachePurgePeriod
	}
	if config.BrowsePeriod == 0 {
		config.BrowsePeriod = DefaultConfig.BrowsePeriod
	}
	if config.RetryPeriod == 0*time.Millisecond {
		config.RetryPeriod = DefaultConfig.RetryPeriod
	}
	return nil
}
