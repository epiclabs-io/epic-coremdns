package main

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Discovery defaults.
const (
	DefaultMDNSTimeout = 5 * time.Second

	mDNSIP4               = "224.0.0.251"
	mDNSIP6               = "ff02::fb"
	mDNSPort              = 5353
	forceUnicastResponses = false
)

var (
	mDNSAddr4 = &net.UDPAddr{IP: net.ParseIP(mDNSIP4), Port: mDNSPort}
	mDNSAddr6 = &net.UDPAddr{IP: net.ParseIP(mDNSIP6), Port: mDNSPort}
)

type cacheEntry struct {
	expires time.Time
	rr      dns.RR
}
type cnameEntry struct {
	expires time.Time
	cname   dns.CNAME
}

type mDNSClient struct {
	// Unicast
	uc4, uc6 *net.UDPConn

	// Multicast
	mc4, mc6 *net.UDPConn

	closed   int32
	closedCh chan struct{}
	lock     sync.RWMutex
	cache    map[string][]cacheEntry
	cnames   map[string]*cnameEntry
	signal   chan struct{}
	msgs     chan *dns.Msg
}

func newmDNSClient() (*mDNSClient, error) {
	uc4, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	uc6, _ := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
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

	msgs := make(chan *dns.Msg, 32)

	c := &mDNSClient{
		uc4:      uc4,
		uc6:      uc6,
		mc4:      mc4,
		mc6:      mc6,
		closedCh: make(chan struct{}),
		signal:   make(chan struct{}),
		msgs:     msgs,
		cache:    make(map[string][]cacheEntry),
		cnames:   make(map[string]*cnameEntry),
	}

	go c.recv(c.uc4, msgs)
	go c.recv(c.uc6, msgs)
	go c.recv(c.mc4, msgs)
	go c.recv(c.mc6, msgs)

	go c.autoPurgeCache()
	go c.serviceQuery("_workstation._tcp.local")

	go c.processMessages()

	return c, nil
}

func newCacheEntry(rr dns.RR) cacheEntry {
	return cacheEntry{
		expires: time.Now().Add(time.Second * time.Duration(rr.Header().Ttl)),
		rr:      rr,
	}
}

func newCnameEntry(cname *dns.CNAME) *cnameEntry {
	return &cnameEntry{
		expires: time.Now().Add(time.Second * time.Duration(cname.Header().Ttl)),
		cname:   *cname,
	}
}

func (c *mDNSClient) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		// something else already closed it
		return nil
	}
	close(c.closedCh)
	if c.uc4 != nil {
		_ = c.uc4.Close()
	}
	if c.uc6 != nil {
		_ = c.uc6.Close()
	}
	if c.mc4 != nil {
		_ = c.mc4.Close()
	}
	if c.mc6 != nil {
		_ = c.mc6.Close()
	}

	return nil
}

func (c *mDNSClient) purgeCache() {
	c.lock.Lock()
	defer c.lock.Unlock()

	now := time.Now()
	for domain, entries := range c.cache {
		var newEntries []cacheEntry
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

func (c *mDNSClient) autoPurgeCache() {
	ticker := time.NewTicker(1 * time.Minute)
	for {
		select {
		case <-ticker.C:
			c.purgeCache()
		case <-c.closedCh:
			return
		}
	}
}

func (c *mDNSClient) processMessages() {
	for {
		select {
		case <-c.closedCh:
			return
		case replies := <-c.msgs:
			func() {
				c.lock.Lock()
				defer c.lock.Unlock()
				records := append(replies.Answer, replies.Extra...)
			process_replies:
				for _, record := range records {
					name := record.Header().Name
					if record.Header().Rrtype == dns.TypeCNAME {
						c.cnames[name] = newCnameEntry(record.(*dns.CNAME))
					} else {
						entries := c.cache[name]
						for i, entry := range entries {
							if dns.IsDuplicate(entry.rr, record) {
								entries[i] = newCacheEntry(record)
								continue process_replies
							}
						}
						c.cache[name] = append(entries, newCacheEntry(record))
					}
				}
			}()
			s := c.signal
			c.signal = make(chan struct{})
			close(s)
		}
	}
}

func (c *mDNSClient) getCachedAnswers(domain string, recordType uint16, cnames map[string]dns.RR) []dns.RR {
	c.lock.Lock()
	defer c.lock.Unlock()

	chain, target := c.resolveCname(domain)

	var answers []dns.RR

	entries := c.cache[target]
	if entries != nil {
		now := time.Now()
		for _, entry := range entries {
			if entry.rr.Header().Rrtype == recordType && entry.expires.After(now) {
				rr := entry.rr
				rr.Header().Ttl = uint32(entry.expires.Sub(now).Seconds())
				answers = append(answers, rr)
			}
		}
	}
	if len(answers) > 0 {
		for _, cname := range chain {
			cnames[cname.Header().Name] = cname
		}
	}
	return answers
}

func (c *mDNSClient) resolveCname(target string) ([]dns.RR, string) {
	var chain []dns.RR
	for {
		entry := c.cnames[target]
		if entry == nil {
			return chain, target
		}
		chain = append(chain, &entry.cname)
		target = entry.cname.Target
	}
}

func (c *mDNSClient) serviceQuery(domain string) {
	for {
		domain = strings.Trim(domain, ".") + "."
		q := new(dns.Msg)
		q.SetQuestion(domain, dns.TypePTR)
		q.Question[0].Qclass |= 1 << 15
		q.RecursionDesired = false
		if err := c.send(q); err != nil {
			log.Printf("error: %s", err)
		}
		time.Sleep(1 * time.Second)
	}
}

func (c *mDNSClient) QueryRecords(ctx context.Context, name string, questionTypes ...uint16) ([]dns.RR, error) {
	name = strings.Trim(name, ".") + "."

	questions := make([]dns.Question, len(questionTypes))
	for i, recordType := range questionTypes {
		questions[i] = dns.Question{
			Name:   name,
			Qtype:  recordType,
			Qclass: dns.ClassINET,
		}
	}
	return c.query(ctx, questions...)
}

func (c *mDNSClient) query(ctx context.Context, questions ...dns.Question) ([]dns.RR, error) {
	// Start listening for response packets

	// RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Question
	// Section
	//
	// In the Question Section of a Multicast DNS query, the top bit of the qclass
	// field is used to indicate that unicast responses are preferred for this
	// particular question.  (See Section 5.4.)
	for _, q := range questions {
		q.Qclass |= 1 << 15
	}

	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.Question = questions
	msg.RecursionDesired = false

	fillAnswers := func() []dns.RR {
		var records []dns.RR
		cnames := make(map[string]dns.RR)
		for _, question := range questions {
			if question.Qtype == dns.TypeCNAME {
				c.lock.Lock()
				entry := c.cnames[question.Name]
				c.lock.Unlock()
				if entry == nil {
					return nil
				}
				records = append(records, &entry.cname)
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
		return append(answers, records...)
	}

	if answers := fillAnswers(); answers != nil {
		return answers, nil
	}

	ticker := time.NewTicker(200 * time.Millisecond)

	if err := c.send(msg); err != nil {
		return nil, err
	}

	for ctx.Err() == nil {
		select {
		case <-ticker.C:
			if err := c.send(msg); err != nil {
				return nil, err
			}
		case <-c.signal:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if records := fillAnswers(); records != nil {
			return records, nil
		}
	}

	return nil, ctx.Err()
}

func (c *mDNSClient) recv(l *net.UDPConn, msgCh chan *dns.Msg) {
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
		select {
		case msgCh <- msg:
		case <-c.closedCh:
			return
		}
	}
}

func (c *mDNSClient) send(q *dns.Msg) error {
	buf, err := q.Pack()
	if err != nil {
		return err
	}

	if c.uc4 != nil {
		c.uc4.WriteToUDP(buf, mDNSAddr4)
	}
	if c.uc6 != nil {
		c.uc6.WriteToUDP(buf, mDNSAddr6)
	}

	return nil
}
