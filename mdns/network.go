package mdns

import (
	"github.com/miekg/dns"
)

// transport is an interface to abstract the network transport and facilitate testing
type transport interface {
	Send(*dns.Msg) error
	Receive() <-chan *dns.Msg
	Close()
}
