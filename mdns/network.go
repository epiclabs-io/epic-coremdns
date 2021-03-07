package mdns

import (
	"github.com/miekg/dns"
)

type transport interface {
	Send(*dns.Msg) error
	Receive() <-chan *dns.Msg
	Close()
}
