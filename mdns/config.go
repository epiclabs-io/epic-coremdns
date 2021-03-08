package mdns

import (
	"net"
	"time"

	"github.com/epiclabs-io/epicmdns/mdns/udptransport"
	"github.com/tilinna/clock"
)

// Config contains the configuration of the mDNS client
type Config struct {
	ForceUnicastResponses bool          // whether to force unicast according to RFC 6762, section 18.12.
	BindIPAddressV4       net.IP        // IPv4 interface to bind to
	BindIPAddressV6       net.IP        // IPv6 interface to bind to
	MinTTL                uint32        // minimum TTL to keep records for, overriding mDNS response
	BrowseServices        []string      // List of services to scan and keep updated
	BrowsePeriod          time.Duration // How often scan the list of services
	CachePurgePeriod      time.Duration // How often clean the cache for stale records
	RetryPeriod           time.Duration // How often retry mDNS queries
	Transport             transport     // Network transport. Defaults to UDP. Useful for testing
	Clock                 clock.Clock   // Time reference. Defaults to system time. Useful for testing
}

// DefaultConfig represents the defaut mDNS config
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

// ApplyDefaults fills the missing fields with sane default values
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
