package mdns

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/epiclabs-io/epicmdns/mdns/udptransport"
	"github.com/epiclabs-io/ticker"
	"github.com/miekg/dns"
	"github.com/tilinna/clock"
)

// Discovery defaults.
const (
	defaultBrowsePeriod = 60
)

type Config struct {
	ForceUnicastResponses bool
	BindIPAddressV4       net.IP
	BindIPAddressV6       net.IP
	MinTTL                uint32
	BrowseServices        []string
	BrowsePeriod          uint32
	Transport             transport
	Clock                 clock.Clock
}

type Client struct {
	Config
	closed       int32
	closedCh     chan struct{}
	lock         sync.RWMutex
	cache        map[string][]*cacheEntry
	cnames       map[string]*cacheEntry
	signal       *signal
	purgeTicker  *ticker.Ticker
	browseTicker *ticker.Ticker
}

func New(config *Config) (*Client, error) {
	if config.BindIPAddressV4 == nil {
		config.BindIPAddressV4 = net.IPv4zero
	}
	if config.BindIPAddressV6 == nil {
		config.BindIPAddressV6 = net.IPv6zero
	}
	if config.Transport == nil {
		transport, err := udptransport.New(&udptransport.Config{
			BindIPAddressV4: config.BindIPAddressV4,
			BindIPAddressV6: config.BindIPAddressV6,
		})
		if err != nil {
			return nil, err
		}
		config.Transport = transport
	}
	if config.Clock == nil {
		config.Clock = clock.Realtime()
	}

	if config.BrowsePeriod == 0 {
		config.BrowsePeriod = defaultBrowsePeriod
	}

	c := &Client{
		Config:   *config,
		closedCh: make(chan struct{}),
		signal:   newSignal(),
		cache:    make(map[string][]*cacheEntry),
		cnames:   make(map[string]*cacheEntry),
	}

	c.purgeTicker = ticker.New(&ticker.Config{
		Clock:    config.Clock,
		Interval: 1 * time.Minute,
		Callback: func() { c.purgeCache() },
	})

	c.browseTicker = ticker.New(&ticker.Config{
		Clock:    config.Clock,
		Interval: time.Duration(c.BrowsePeriod) * time.Second,
		Callback: func() {
			for _, s := range c.BrowseServices {
				c.serviceQuery(s)
			}
		},
	})

	go c.messageLoop()

	return c, nil
}

func (c *Client) newCacheEntry(rr dns.RR, now time.Time) *cacheEntry {
	ttl := rr.Header().Ttl
	if ttl < c.MinTTL {
		ttl = c.MinTTL
	}
	return &cacheEntry{
		expires: now.Add(time.Second * time.Duration(ttl)),
		rr:      rr,
	}
}

func (c *Client) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		// something else already closed it
		return nil
	}
	close(c.closedCh)
	c.Transport.Close()
	c.purgeTicker.Stop()
	c.browseTicker.Stop()
	return nil
}

func (c *Client) purgeCache() {
	c.lock.Lock()
	defer c.lock.Unlock()

	now := c.Clock.Now()
	for domain, entries := range c.cache {
		var newEntries []*cacheEntry
		for _, entry := range entries {
			if entry.expires.After(now) {
				newEntries = append(newEntries, entry)
			}
		}
		if len(newEntries) > 0 {
			c.cache[domain] = newEntries
		} else {
			delete(c.cache, domain)
		}
		for domain, entry := range c.cnames {
			if entry.expires.After(now) {
				delete(c.cnames, domain)
			}
		}
	}
}

func (c *Client) processMessage(reply *dns.Msg) {
	c.lock.Lock()
	defer c.lock.Unlock()

	records := append(reply.Answer, reply.Extra...)
	now := c.Clock.Now()

process_replies:
	for _, record := range records {
		name := record.Header().Name
		if record.Header().Rrtype == dns.TypeCNAME {
			c.cnames[name] = c.newCacheEntry(record.(*dns.CNAME), now)
		} else {
			entries := c.cache[name]
			for i, entry := range entries {
				if dns.IsDuplicate(entry.rr, record) {
					if record.Header().Ttl > entry.ttl(now) {
						entries[i] = c.newCacheEntry(record, now)
					}
					continue process_replies
				}
			}
			c.cache[name] = append(entries, c.newCacheEntry(record, now))
		}
	}
}

func (c *Client) messageLoop() {
	for {
		select {
		case <-c.closedCh:
			return
		case reply := <-c.Transport.Receive():
			c.processMessage(reply)
			c.signal.raise()
		}
	}
}

func (c *Client) getCachedAnswers(domain string, recordType uint16, cnames map[string]dns.RR) []dns.RR {
	chain, target := c.resolveCname(domain)

	var answers []dns.RR

	entries := c.cache[target]
	now := c.Clock.Now()
	if entries != nil {
		for _, entry := range entries {
			if entry.rr.Header().Rrtype == recordType && entry.expires.After(now) {
				rr := entry.rr
				rr.Header().Ttl = entry.ttl(now)
				answers = append(answers, rr)
			}
		}
	}
	if len(answers) == 0 {
		return nil
	}

	for _, cname := range chain {
		cnames[cname.Header().Name] = cname
	}

	var followup []dns.RR
	switch recordType {
	case dns.TypePTR:
		for _, rr := range answers {
			ptr := rr.(*dns.PTR)
			followup = append(followup, c.getCachedAnswers(ptr.Ptr, dns.TypeTXT, cnames)...)
			followup = append(followup, c.getCachedAnswers(ptr.Ptr, dns.TypeSRV, cnames)...)
		}
	case dns.TypeSRV:
		for _, rr := range answers {
			srv := rr.(*dns.SRV)
			followup = append(followup, c.getCachedAnswers(srv.Target, dns.TypeA, cnames)...)
			followup = append(followup, c.getCachedAnswers(srv.Target, dns.TypeAAAA, cnames)...)
		}
	}

	return append(answers, followup...)
}

func (c *Client) resolveCname(target string) ([]dns.RR, string) {
	var chain []dns.RR
	now := c.Clock.Now()
	for {
		entry := c.cnames[target]
		if entry == nil {
			return chain, target
		}
		entry.rr.Header().Ttl = entry.ttl(now)
		chain = append(chain, entry.rr)
		target = entry.cname().Target
	}
}

func (c *Client) serviceQuery(service string) {
	service = strings.Trim(service, ".") + "."
	q := new(dns.Msg)
	q.SetQuestion(service, dns.TypePTR)
	if c.ForceUnicastResponses {
		q.Question[0].Qclass |= 1 << 15
	}
	q.RecursionDesired = false
	if err := c.Transport.Send(q); err != nil {
		log.Printf("error: %s", err)
	}
}

func (c *Client) QueryRecords(ctx context.Context, name string, questionTypes ...uint16) ([]dns.RR, error) {
	name = strings.Trim(name, ".") + "."
	questions := make([]dns.Question, len(questionTypes))

	for i, recordType := range questionTypes {
		questions[i] = dns.Question{
			Name:   name,
			Qtype:  recordType,
			Qclass: dns.ClassINET,
		}
	}
	return c.Query(ctx, questions...)
}

func (c *Client) answerQuestions(questions []dns.Question) []dns.RR {
	var records []dns.RR
	cnames := make(map[string]dns.RR)

	c.lock.Lock()
	defer c.lock.Unlock()

	for _, question := range questions {
		if question.Qtype == dns.TypeCNAME {
			entry := c.cnames[question.Name]
			if entry == nil {
				return nil
			}
			records = append(records, entry.rr)
		} else {
			cachedAnswers := c.getCachedAnswers(question.Name, question.Qtype, cnames)
			if len(cachedAnswers) == 0 {
				return nil
			}
			records = append(records, cachedAnswers...)
		}
	}
	answers := make([]dns.RR, 0, len(cnames)+len(records))
	for _, cname := range cnames {
		answers = append(answers, cname)
	}
	return copyRecords(append(answers, records...))
}

func (c *Client) Query(ctx context.Context, questions ...dns.Question) ([]dns.RR, error) {
	// Start listening for response packets

	// RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Question
	// Section
	//
	// In the Question Section of a Multicast DNS query, the top bit of the qclass
	// field is used to indicate that unicast responses are preferred for this
	// particular question.  (See Section 5.4.)
	if c.ForceUnicastResponses {
		for _, q := range questions {
			q.Qclass |= 1 << 15
		}
	}

	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.Question = questions
	msg.RecursionDesired = false

	if answers := c.answerQuestions(questions); answers != nil {
		return answers, nil
	}

	ticker := c.Clock.NewTicker(200 * time.Millisecond)

	if err := c.Transport.Send(msg); err != nil {
		return nil, err
	}

	for ctx.Err() == nil {
		select {
		case <-ticker.C:
			if err := c.Transport.Send(msg); err != nil {
				return nil, err
			}
		case <-c.signal.wait():
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if records := c.answerQuestions(questions); records != nil {
			return records, nil
		}
	}

	return nil, ctx.Err()
}

func copyRecords(source []dns.RR) []dns.RR {
	dest := make([]dns.RR, len(source))
	for i, r := range source {
		dest[i] = dns.Copy(r)
	}
	return dest
}
