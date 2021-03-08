package epicmdns

import (
	"context"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("epicmdns")

type mdnsclient interface {
	Query(ctx context.Context, questions ...dns.Question) ([]dns.RR, error)
}

type Plugin struct {
	mdns   mdnsclient
	Next   plugin.Handler
	domain string
}

func (p Plugin) Name() string { return "epicmdns" }

func (p Plugin) ToLocal(input string) string {
	// Replace input domain with .local
	return strings.TrimSuffix(input, p.domain) + ".local."
}

func (p Plugin) FromLocal(local string) string {
	// Replace .local to our domain
	return strings.TrimSuffix(local, ".local.") + p.domain
}

func (p Plugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	msg.RecursionAvailable = true
	name := r.Question[0].Name
	log.Debugf("Looking for name: %s", name)

	if !strings.HasSuffix(name, p.domain) {
		log.Debugf("Ignoring %q not in configured domain %q", name, p.domain)
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}

	// Translate questions to `.local` domain:
	questions := make([]dns.Question, len(r.Question))
	for i, q := range r.Question {
		questions[i] = dns.Question{
			Name:   p.ToLocal(q.Name),
			Qtype:  q.Qtype,
			Qclass: q.Qclass,
		}
	}

	// query mDNS
	answers, err := p.mdns.Query(ctx, questions...)
	if err != nil {
		log.Debugf("Error looking up %s: %s", name, err)
		return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
	}

	// map responses to configured domain:
	for _, ans := range answers {
		ans.Header().Name = p.FromLocal(ans.Header().Name)
		switch r := ans.(type) {
		case *dns.CNAME:
			r.Target = p.FromLocal(r.Target)
		case *dns.PTR:
			r.Ptr = p.FromLocal(r.Ptr)
		case *dns.SRV:
			r.Target = p.FromLocal(r.Target)
		}
	}

	// return to CoreDNS
	msg.Answer = answers
	return dns.RcodeSuccess, w.WriteMsg(msg)
}
