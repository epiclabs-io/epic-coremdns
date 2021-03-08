package mdns

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/epiclabs-io/ut"
	"github.com/miekg/dns"
	"github.com/tilinna/clock"
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

func rr2string(cache []dns.RR, cnames map[string]dns.RR) string {
	s := make([]string, len(cache))
	for i, r := range cache {
		s[i] = r.String()
	}
	for _, c := range cnames {
		s = append(s, c.String())
	}
	sort.Slice(s, func(i, j int) bool {
		return strings.Compare(s[i], s[j]) < 0
	})
	return strings.Join(s, "\n")
}

func parseRecords(t *ut.DefaultTestTools, zoneText string) (rr []dns.RR) {
	for _, recordTxt := range strings.Split(strings.Trim(strings.TrimSpace(zoneText), "\n"), "\n") {
		r, err := dns.NewRR(strings.TrimSpace(recordTxt))
		t.Ok(err)
		rr = append(rr, r)
	}
	return rr
}

func equalsMessage(t *ut.DefaultTestTools, file string, msg *dns.Msg) {
	m := msg.Copy()
	m.Id = 0
	t.EqualsTextFile(file, m.String())
}

func dumpCache(c *Client) string {
	var cache []dns.RR
	cnames := make(map[string]dns.RR)
	for _, entries := range c.cache {
		for _, entry := range entries {
			rr := dns.Copy(entry.rr)
			rr.Header().Ttl = entry.ttl(c.Clock.Now())
			cache = append(cache, rr)
		}
	}
	for name, entry := range c.cnames {
		rr := dns.Copy(entry.rr)
		rr.Header().Ttl = entry.ttl(c.Clock.Now())
		cnames[name] = rr
	}
	return rr2string(cache, cnames)
}

var zone = `
_service1._tcp.local.		200	IN	PTR		epic._service1._tcp.local.
_service1._tcp.local.		240	IN	PTR		demo._service1._tcp.local.
epic._service1._tcp.local.	230	IN	SRV		1 2 7979 praetor.epiclabs.io.
demo._service1._tcp.local.	100 IN  SRV		5 6 8080 terminus.epiclabs.io.
demo._service1._tcp.local.	230	IN	TXT		"demo text"
demo._service1._tcp.local.	260	IN	TXT		"more demo text"
epic._service1._tcp.local.	240	IN	TXT		"some text"
praetor.epiclabs.io.		250	IN	CNAME	primus.epiclabs.io.
primus.epiclabs.io			120	IN	A		1.2.3.4
primus.epiclabs.io			110	IN	AAAA	fe80::abc:cdef:0123:4567
terminus.epiclabs.io		2  IN	A		5.6.7.8 ; test MinTTL
www.epiclabs.io				300	IN CNAME	myserver.epiclabs.io.
myserver.epiclabs.io		300	IN	A		10.10.10.10	; duplicate below
myserver.epiclabs.io		400	IN	A		10.10.10.10  ; higher TTL prevails in cache	
`

func TestServiceQuery(tx *testing.T) {
	t := ut.BeginTest(tx, false)
	defer t.FinishTest()

	mt := newMockTransport()
	clk := clock.NewMock(time.Unix(0, 0))

	c, err := New(&Config{
		ForceUnicastResponses: false,
		Transport:             mt,
		BrowseServices:        []string{"service1", "service2"},
		BrowsePeriod:          100 * time.Second,
		Clock:                 clk,
	})
	t.Ok(err)
	defer c.Close()

	go func() {
		for {
			clk.Add(c.BrowsePeriod)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	for i := 0; i < len(c.BrowseServices); i++ {
		msg := <-mt.out
		msg.Id = 0
		equalsMessage(t, fmt.Sprintf("message%02d.txt", i), msg)
	}

	mt = newMockTransport()
	c, err = New(&Config{
		ForceUnicastResponses: true,
		Transport:             mt,
		BrowseServices:        []string{"service1", "service2"},
		Clock:                 clk,
	})
	t.Ok(err)

	for i := 0; i < len(c.BrowseServices); i++ {
		msg := <-mt.out
		msg.Id = 0
		equalsMessage(t, fmt.Sprintf("message%02d-unicast.txt", i), msg)
	}

}

func TestCache(tx *testing.T) {
	t := ut.BeginTest(tx, false)
	defer t.FinishTest()

	clk := clock.NewMock(time.Unix(0, 0))
	mt := newMockTransport()

	c, err := New(&Config{
		Clock:            clk,
		CachePurgePeriod: 5000 * time.Second,
		MinTTL:           50,
		Transport:        mt,
	})
	t.Ok(err)
	defer c.Close()

	c.addToCache(parseRecords(t, zone))

	for _, timestamp := range []int64{0, 60, 105, 125, 205, 225, 235, 245} {
		clk.Set(time.Unix(timestamp, 0))
		cnames := make(map[string]dns.RR)
		cached := c.getCachedAnswers("_service1._tcp.local.", dns.TypePTR, cnames)
		t.EqualsTextFile(fmt.Sprintf("t-%04d.txt", timestamp), rr2string(cached, cnames))
	}

	t.EqualsTextFile("before-purge.txt", dumpCache(c))
	c.purgeCache()
	t.EqualsTextFile("after-purge.txt", dumpCache(c))
}

func TestMessageLoop(tx *testing.T) {
	t := ut.BeginTest(tx, false)
	defer t.FinishTest()

	clk := clock.NewMock(time.Unix(0, 0))
	mt := newMockTransport()

	c, err := New(&Config{
		Clock:     clk,
		Transport: mt,
	})

	t.Ok(err)
	defer c.Close()

	answers := `
	www.epiclabs.io				300	IN CNAME	myserver.epiclabs.io.
	myserver.epiclabs.io		300	IN	A		10.10.10.10	
	`
	extra := `
	demo._service1._tcp.local.	230	IN	TXT		"demo text"
	`

	var msg = new(dns.Msg)
	msg.Answer = parseRecords(t, answers)
	msg.Extra = parseRecords(t, extra)

	go func() {
		mt.in <- msg
	}()

	<-c.signal.waitCh()
	t.EqualsTextFile("cache.txt", dumpCache(c))
}

func TestAnswerQuestions(tx *testing.T) {
	t := ut.BeginTest(tx, false)
	defer t.FinishTest()

	clk := clock.NewMock(time.Unix(0, 0))
	mt := newMockTransport()

	c, err := New(&Config{
		Clock:     clk,
		Transport: mt,
	})

	t.Ok(err)
	defer c.Close()

	c.addToCache(parseRecords(t, zone))

	questionSets := [][]dns.Question{
		{{Name: "www.epiclabs.io.", Qtype: dns.TypeA, Qclass: dns.ClassINET}},
		{{Name: "_service1._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET}},
		{{Name: "www.epiclabs.io.", Qtype: dns.TypeCNAME, Qclass: dns.ClassINET}},
		{{Name: "www.doesnotexist.not.", Qtype: dns.TypeCNAME, Qclass: dns.ClassINET}},
		{{Name: "www.doesnotexist.not.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}},
	}

	for i, qs := range questionSets {
		msg := &dns.Msg{
			Question: qs,
			Answer:   c.answerQuestions(qs),
		}
		equalsMessage(t, fmt.Sprintf("set%02d.txt", i), msg)
	}
}

func TestQuery(tx *testing.T) {

	t := ut.BeginTest(tx, false)
	defer t.FinishTest()

	clk := clock.NewMock(time.Unix(0, 0))
	mt := newMockTransport()

	c, err := New(&Config{
		Clock:       clk,
		Transport:   mt,
		RetryPeriod: 500 * time.Millisecond,
	})

	t.Ok(err)
	defer c.Close()

	ctx := context.Background()

	q := dns.Question{Name: "www.epiclabs.io.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	var wg sync.WaitGroup
	wg.Add(1)
	var queryErr error
	var queryResult []dns.RR
	go func() {
		queryResult, queryErr = c.Query(ctx, q)
		wg.Done()
	}()

	msg := <-mt.out
	equalsMessage(t, "question1.txt", msg)

	answerMsg := new(dns.Msg).SetReply(msg)
	answerMsg.Answer = parseRecords(t, `
	www.epiclabs.io				300	IN CNAME	myserver.epiclabs.io.
	myserver.epiclabs.io		300	IN	A		10.10.10.10	
	`)

	// if time passes without an answer, a retransmit must be sent
	clk.Add(c.RetryPeriod)
	msg2 := <-mt.out
	t.Equals(msg, msg2)

	mt.in <- answerMsg
	wg.Wait()
	t.Ok(queryErr)
	t.EqualsTextFile("answer1.txt", rr2string(queryResult, nil))

	// test query again to trigger cache

	queryResult2, err := c.Query(ctx, q)
	t.Ok(err)
	t.Equals(queryResult, queryResult2)

	// test context cancellation
	// clear the cache by elapsing time
	clk.Add(500 * time.Hour)
	c.purgeCache()

	ctx2, cancel := context.WithCancel(context.Background())
	wg.Add(1)
	go func() {
		queryResult, queryErr = c.Query(ctx2, q)
		wg.Done()
	}()

	// read the outgoing mdns query and ignore it
	msg = <-mt.out

	//cancel context
	cancel()
	wg.Wait()
	t.MustFail(queryErr, "Expected to have an error when context is cancelled")

	c.ForceUnicastResponses = true
	t.Ok(err)

	go func() {
		queryResult, queryErr = c.Query(ctx, q)
	}()

	msg = <-mt.out
	equalsMessage(t, "question-unicast.txt", msg)
}
