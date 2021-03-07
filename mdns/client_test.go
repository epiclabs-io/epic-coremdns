package mdns

import (
	"strings"
	"testing"

	"github.com/epiclabs-io/ut"
	"github.com/miekg/dns"
)

type mockTransport struct {
	out chan *dns.Msg
	in  chan *dns.Msg
}

func newMockTransport() *mockTransport {
	return &mockTransport{
		out: make(chan *dns.Msg),
		in:  make(chan *dns.Msg),
	}
}

func (mt *mockTransport) Send(msg *dns.Msg) error {
	mt.out <- msg
	return nil
}
func (mt *mockTransport) Receive() <-chan *dns.Msg {
	return mt.in
}
func (mt *mockTransport) Close() {

}

func TestServiceQuery(tx *testing.T) {
	t := ut.BeginTest(tx, true)
	defer t.FinishTest()

	mt := newMockTransport()

	c, err := New(&Config{
		ForceUnicastResponses: false,
		Transport:             mt,
	})
	t.Ok(err)

	go c.serviceQuery("_service1._tcp.local")
	msg := <-mt.out
	msg.Id = 0
	t.EqualsFile("message.txt", strings.Split(msg.String(), "\n"))

	c, err = New(&Config{
		ForceUnicastResponses: true,
		Transport:             mt,
	})
	t.Ok(err)

	go c.serviceQuery("_service1._tcp.local")
	msg = <-mt.out
	msg.Id = 0
	t.EqualsFile("message-unicast.txt", strings.Split(msg.String(), "\n"))

}
