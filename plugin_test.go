package epicmdns

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/epiclabs-io/ut"
	"github.com/miekg/dns"
)

type mockMdnsClient struct {
	fail bool
}

func (m *mockMdnsClient) Query(ctx context.Context, questions ...dns.Question) ([]dns.RR, error) {
	if m.fail {
		return nil, errors.New("Failed Query")
	}
	var answer = make([]dns.RR, 6)
	answer[0], _ = dns.NewRR("_service1._tcp.local.		200	IN	PTR		epic._service1._tcp.local.")
	answer[1], _ = dns.NewRR("epic._service1._tcp.local.	230	IN	SRV		1 2 7979 praetor.local.")
	answer[2], _ = dns.NewRR(`epic._service1._tcp.local.	240	IN	TXT		"some text"`)
	answer[3], _ = dns.NewRR("praetor.local.		250	IN	CNAME	primus.local.")
	answer[4], _ = dns.NewRR("primus.local.			120	IN	A		1.2.3.4")
	answer[5], _ = dns.NewRR("primus.local.			110	IN	AAAA	fe80::abc:cdef:0123:4567")

	return answer, nil
}

type mockResponseWriter struct {
	msg *dns.Msg
}

func (mrw *mockResponseWriter) LocalAddr() net.Addr         { panic("not implemented") }
func (mrw *mockResponseWriter) RemoteAddr() net.Addr        { panic("not implemented") }
func (mrw *mockResponseWriter) WriteMsg(msg *dns.Msg) error { mrw.msg = msg; return nil }
func (mrw *mockResponseWriter) Write([]byte) (int, error)   { panic("not implemented") }
func (mrw *mockResponseWriter) Close() error                { panic("not implemented") }
func (mrw *mockResponseWriter) TsigStatus() error           { panic("not implemented") }
func (mrw *mockResponseWriter) TsigTimersOnly(bool)         { panic("not implemented") }
func (mrw *mockResponseWriter) Hijack()                     { panic("not implemented") }

type mockNextPlugin struct {
}

func (mnp *mockNextPlugin) ServeDNS(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
	return 0, errors.New("ServeDNS errored")
}
func (mnp *mockNextPlugin) Name() string { return "mocknextplugin" }

func TestServe(tx *testing.T) {
	t := ut.BeginTest(tx, false)
	defer t.FinishTest()

	client := &mockMdnsClient{}
	p := &Plugin{
		mdns:   client,
		Next:   &mockNextPlugin{},
		domain: ".epiclabs.io.",
	}

	mrw := &mockResponseWriter{}
	q := dns.Question{Name: "_service1._tcp.epiclabs.io.", Qtype: dns.TypePTR, Qclass: dns.ClassINET}
	msg := new(dns.Msg)
	msg.Question = []dns.Question{q}

	code, err := p.ServeDNS(context.Background(), mrw, msg)
	t.Ok(err)
	t.Equals(dns.RcodeSuccess, code)
	mrw.msg.Id = 0
	t.EqualsTextFile("query.txt", mrw.msg.String())

	client.fail = true
	code, err = p.ServeDNS(context.Background(), mrw, msg)
	t.MustFail(err, "Expected ServeDNS to fail since query failed")
	t.Equals(dns.RcodeSuccess, code)

	client.fail = false
	q = dns.Question{Name: "www.someotherdomain.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg = new(dns.Msg)
	msg.Question = []dns.Question{q}

	code, err = p.ServeDNS(context.Background(), mrw, msg)
	t.MustFail(err, "Expected ServeDNS to fail since requested domain is not the configured domain")
	t.Equals(dns.RcodeSuccess, code)

}
