package mdns

import (
	"context"
	"log"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/epiclabs-io/ticker"
	"github.com/miekg/dns"
)

// Client represents a mDNS client
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

// New builds a mDNS Client with the given configuration
func New(config *Config) (*Client, error) {
	// apply defaults to missing config parameters:
	if err := config.ApplyDefaults(); err != nil {
		return nil, err
	}

	c := &Client{
		Config:   *config,
		closedCh: make(chan struct{}),
		signal:   newSignal(),
		cache:    make(map[string][]*cacheEntry),
		cnames:   make(map[string]*cacheEntry),
	}

	// configure periodic tasks
	c.purgeTicker = ticker.New(&ticker.Config{
		Clock:    config.Clock,
		Interval: config.CachePurgePeriod,
		Callback: func() { c.purgeCache() },
	})

	c.browseTicker = ticker.New(&ticker.Config{
		Clock:    config.Clock,
		Interval: c.BrowsePeriod,
		Callback: func() {
			for _, s := range c.BrowseServices {
				c.serviceQuery(s)
			}
		},
	})

	// start reading incoming messages
	go c.messageLoop()

	return c, nil
}

// Close shuts down the client
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

// messageLoop reads the transport and adds received
// records to the cache. It signals outstanding queries when
// records are in cache
func (c *Client) messageLoop() {
	for {
		select {
		case <-c.closedCh:
			return
		case reply := <-c.Transport.Receive():
			c.addToCache(append(reply.Answer, reply.Extra...))
			c.signal.raise()
		}
	}
}

// serviceQuery sends out a PTR query to discover
// servicess
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

// answerQuestions takes a list of DNS questions and attempts
// to answer all of them. If any question cannot be answered,
// none are answered.
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

// Query takes a list of questions and tries to resove them until
// answers are received or context is cancelled.
func (c *Client) Query(ctx context.Context, questions ...dns.Question) ([]dns.RR, error) {

	// RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Question
	// Section
	//
	// In the Question Section of a Multicast DNS query, the top bit of the qclass
	// field is used to indicate that unicast responses are preferred for this
	// particular question.  (See Section 5.4.)
	if c.ForceUnicastResponses {
		for i, _ := range questions {
			questions[i].Qclass |= 1 << 15
		}
	}

	// build question message
	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.Question = questions
	msg.RecursionDesired = false

	// first, try to answer the question off the cache, without asking over the network
	if answers := c.answerQuestions(questions); answers != nil {
		return answers, nil
	}

	// if all the answers are not in cache, ask over the network:
	if err := c.Transport.Send(msg); err != nil {
		return nil, err
	}

	// prepare a ticker for retries:
	ticker := c.Clock.NewTicker(c.RetryPeriod)

	for ctx.Err() == nil {
		select {
		case <-ticker.C:
			// resend question over the network
			if err := c.Transport.Send(msg); err != nil {
				return nil, err
			}
		case <-c.signal.waitCh(): // new data received, exit select and check answers
		case <-ctx.Done(): // context cancelled/timed out
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
