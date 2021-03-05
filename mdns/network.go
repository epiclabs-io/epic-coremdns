package mdns

import (
	"github.com/miekg/dns"
)

type Transport interface {
	Send(*dns.Msg) error
	Receive() <-chan *dns.Msg
	Close()
}
