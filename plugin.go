package epicmdns

import "github.com/epiclabs-io/epicmdns/mdns"

type Plugin struct {
	mdns *mdns.Client
}
