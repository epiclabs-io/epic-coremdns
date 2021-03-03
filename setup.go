package epicmdns

import (
	"fmt"

	"github.com/coredns/caddy"
)

func init() {
	caddy.RegisterPlugin("epicmdns", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	config, err := parseConfig(c)
	if err != nil {
		return err
	}
	fmt.Println(*config)
	return nil
}
