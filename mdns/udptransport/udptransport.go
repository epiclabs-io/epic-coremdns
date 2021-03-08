package udptransport

import (
	"errors"
	"net"

	"github.com/miekg/dns"
)

const (
	mDNSIP4  = "224.0.0.251"
	mDNSIP6  = "ff02::fb"
	mDNSPort = 5353
)

var (
	mDNSAddr4 = &net.UDPAddr{IP: net.ParseIP(mDNSIP4), Port: mDNSPort}
	mDNSAddr6 = &net.UDPAddr{IP: net.ParseIP(mDNSIP6), Port: mDNSPort}
)

// UDPTransport implements the transport interface with UDP
type UDPTransport struct {
	uc4, uc6 *net.UDPConn // unicasts sockets
	mc4, mc6 *net.UDPConn // multicast sockets
	closed   chan struct{}
	msgs     chan *dns.Msg
}

// Config contains the configuration for UDPTransport
type Config struct {
	BindIPAddressV4 net.IP // Address to bind to
	BindIPAddressV6 net.IP
}

// New instantiates a new UDPTransport
func New(config *Config) (*UDPTransport, error) {
	if config.BindIPAddressV4 == nil {
		config.BindIPAddressV4 = net.IPv4zero
	}
	if config.BindIPAddressV6 == nil {
		config.BindIPAddressV6 = net.IPv6zero
	}
	uc4, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: config.BindIPAddressV4, Port: 0})
	uc6, _ := net.ListenUDP("udp6", &net.UDPAddr{IP: config.BindIPAddressV6, Port: 0})
	if uc4 == nil && uc6 == nil {
		return nil, errors.New("Failed to bind to any unicast UDP port")
	}

	mc4, _ := net.ListenMulticastUDP("udp4", nil, mDNSAddr4)
	mc6, _ := net.ListenMulticastUDP("udp6", nil, mDNSAddr6)
	if uc4 == nil && uc6 == nil {
		if uc4 != nil {
			_ = uc4.Close()
		}
		if uc6 != nil {
			_ = uc6.Close()
		}
		return nil, errors.New("Failed to bind to any multicast TCP port")
	}

	msgs := make(chan *dns.Msg)
	closed := make(chan struct{})

	go recv(uc4, msgs, closed)
	go recv(uc6, msgs, closed)
	go recv(mc4, msgs, closed)
	go recv(mc6, msgs, closed)

	return &UDPTransport{
		uc4:    uc4,
		uc6:    uc6,
		mc4:    mc4,
		mc6:    mc6,
		closed: closed,
		msgs:   msgs,
	}, nil
}

// Send sends a dns message over all UDP connections
func (u *UDPTransport) Send(msg *dns.Msg) error {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}

	if u.uc4 != nil {
		u.uc4.WriteToUDP(buf, mDNSAddr4)
	}
	if u.uc6 != nil {
		u.uc6.WriteToUDP(buf, mDNSAddr6)
	}

	return nil
}

// Receive returns a channel that outputs received dns messages
func (u *UDPTransport) Receive() <-chan *dns.Msg {
	return u.msgs
}

// Close shuts down all sockets
func (u *UDPTransport) Close() {
	close(u.closed)
}

// recv reads and parses all DNS packets coming from the socket and sends them
// over the channel
func recv(l *net.UDPConn, msgCh chan *dns.Msg, closed chan struct{}) {
	if l == nil {
		return
	}

	buf := make([]byte, 65536)
	for {
		n, err := l.Read(buf)
		if err != nil {
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			continue
		}
		if msg.Response == false {
			continue
		}

		for _, rr := range msg.Answer {
			rr.Header().Class &= 0x7FFF
		}

		select {
		case msgCh <- msg:
		case <-closed:
			return
		}
	}
}
