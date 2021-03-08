package mdns

import (
	"time"

	"github.com/miekg/dns"
)

// cacheEntry keeps track of a dns record in cache
type cacheEntry struct {
	expires time.Time
	rr      dns.RR
}

// ttl computes back the TTL based on what time it is now
func (e *cacheEntry) ttl(now time.Time) uint32 {
	if ttl := e.expires.Sub(now).Seconds(); ttl > 0 {
		return uint32(ttl)
	}
	return 0
}

// cname casts the record to a CNAME struct
func (e *cacheEntry) cname() *dns.CNAME {
	return e.rr.(*dns.CNAME)
}

// newCacheEntry creates a new DNS record cache entry
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

// purgeCache evicts expired records off the cache
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
	}
	for domain, entry := range c.cnames {
		if entry.expires.After(now) {
			delete(c.cnames, domain)
		}
	}
}

// addToCache adds the list of records to the cache
// updating existing items if necessary
func (c *Client) addToCache(records []dns.RR) {
	c.lock.Lock()
	defer c.lock.Unlock()

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

// resolveCname attempts to retrieve from the cache the list of related cnames
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

// getCachedAnswers attempts to retrieve from cache a collection of records that answer a single question
// trying to facilitate records that would be requested as well
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
