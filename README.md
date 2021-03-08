# epic-mdns mDNS CoreDNS plugin
![Go](https://github.com/epiclabs-io/epicmdns/workflows/Go/badge.svg)
[![Go Report](https://goreportcard.com/badge/github.com/epiclabs-io/epicmdns)](https://goreportcard.com/report/github.com/epiclabs-io/epicmdns)
[![Godoc Reference](https://godoc.org/github.com/epiclabs-io/epicmdns?status.svg)](https://pkg.go.dev/github.com/epiclabs-io/epicmdns)

This CoreDNS plug-in bridges DNS to your local network, translating found `.local` hosts to any preconfigured domain

Technically, it supports all kinds of records. Additionally, it can browse the network periodically to discover services (DNS-SD).

## How to use:

First, add the following to your CoreDNS `plugin.cfg` and recompile CoreDNS:

```
epicmdns:github.com/epiclabs-io/epicmdns
```

Second, add to your `Corefile`:

```
example.com {
    cancel
	epicmdns example.com {
	}
}
```

The above exposes all found mDNS `.local` services and hosts under `example.com`. Thus, `myserver.local` in mDNS can now be resolved as `myserver.example.com`.

## Advanced configuration

```
epicmdns <domain> {              # domain to map to
    min_ttl <seconds>            # (int, seconds) minimum TTL to keep records for, overriding mDNS response. Default 300s
    browse_period <seconds>      # (int, seconds) period to keep service list updated. Default 60s
    force_unicast                # (bool) whether we ask hosts to respond directly to us if possible. Default false
    ip4 <ip>                     # (string, IP address) IPv4 interface to bind to. Defaults to 0.0.0.0
    ip6 <ipv6>                   # (string, IP address) IPv6 interface to bind to. Defaults to 0::0
    browse <service>             # (string) repeat as necessary. List of services to scan and keep updated
    browse_period  <seconds>     # (int, seconds) How often scan the list of services. Default 60s
    retry_period <seconds>       # (float, seconds) How often retry mDNS queries. Default 0.250s
    cache_purge_period <seconds> # (int, seconds) How often clean the cache for stale records. Default 300s
```

## Full examples

### Expose `.local` directly to regular DNS
This example exposes `.local` hosts to conventional DNS, as-is. Useful to help non-mDNS aware client devices, such as Android and older versions of Windows in the LAN discover mDNS services and hosts.

```
local {
	debug
	log
	cancel
	epicmdns local {
		min_ttl 120
        browse_period 60
        browse _workstation._tcp.local
        browse _etcd-server-ssl._tcp
	}
	records local {
		@  60 IN SOA myserver admin.myserver 1 120 120 120 300
	}
}
```

### Map `.local` to an arbitrary domain
This example exposes `.local` hosts to conventional DNS, mapping them to `.epiclabs.io`

```
epiclabs.io {
	debug
	log
	cancel
	epicmdns epiclabs.io
}
```

## Your Feedback

Add your issue here on GitHub. Feel free to get in touch if you have any questions.

## Author(s)

This package is written and maintained by Javier Peletier ([@jpeletier](https://github.com/jpeletier)) - [Epic Labs](https://www.epiclabs.io)