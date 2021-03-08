package epicmdns

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/epiclabs-io/epicmdns/mdns"
)

// register with CoreDNS on module load
func init() {
	caddy.RegisterPlugin("epicmdns", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

// setup parses the configuration and launches the plug-in
func setup(c *caddy.Controller) error {
	// parse configuration
	config, err := parseConfig(&c.Dispenser)
	if err != nil {
		return err
	}

	// instantiate mdns resolver
	mdnsClient, err := mdns.New(&config.Config)
	if err != nil {
		return err
	}

	// setup plugin
	p := mdnsPlugin{
		mdns:   mdnsClient,
		domain: config.Domain,
	}

	// Add plug-in to the chain
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})

	return nil
}
