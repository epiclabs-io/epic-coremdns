package epicmdns

import (
	"fmt"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/epiclabs-io/epicmdns/mdns"
)

func init() {
	caddy.RegisterPlugin("epicmdns", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	config, err := parseConfig(&c.Dispenser)
	if err != nil {
		return err
	}

	mdnsClient, err := mdns.New(&config.Config)
	if err != nil {
		return err
	}
	p := Plugin{
		mdns:   mdnsClient,
		domain: config.Domain,
	}

	c.OnStartup(func() error {
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		fmt.Println("Next")
		p.Next = next
		return p
	})

	return nil
}
