package mdns

import (
	"time"

	"github.com/miekg/dns"
)

type cacheEntry struct {
	expires time.Time
	rr      dns.RR
}

func (e *cacheEntry) ttl(now time.Time) uint32 {
	if ttl := e.expires.Sub(now).Seconds(); ttl > 0 {
		return uint32(ttl)
	}
	return 0
}

func (e *cacheEntry) cname() *dns.CNAME {
	return e.rr.(*dns.CNAME)
}
