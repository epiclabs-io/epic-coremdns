package epicmdns

import (
	"strings"
	"testing"

	"github.com/coredns/caddy/caddyfile"
	"github.com/epiclabs-io/ut"
)

func TestConfig(tx *testing.T) {
	t := ut.BeginTest(tx, false)
	defer t.FinishTest()

	d := caddyfile.NewDispenser("file", strings.NewReader(`
	epicmdns epiclabs.io {
		min_ttl 120
		browse_period 60
		force_unicast
		ip4 1.2.3.4
		ip6 fe80::abc:cdef:0123:4567
		browse _workstation._tcp.local
		browse service1._tcp.local
		browse_period 120
		retry_period 0.300
		cache_purge_period 60
	}
	`))

	config, err := parseConfig(&d)
	t.Ok(err)
	t.EqualsFile("config.json", config)

}
