package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
)

func main() {

	client, err := newmDNSClient(&Config{
		ForceUnicastResponses: false,
		MinTTL:                60,
	})
	if err != nil {
		log.Fatal(err)
	}

	q := func(domain string, id int, recordTypes ...uint16) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		answers, err := client.QueryRecords(ctx, domain, recordTypes...)
		if err != nil {
			//		log.Fatal(err)
		}
		for _, ans := range answers {
			fmt.Println(id, ans)
		}
		fmt.Println("-----")
	}
	fmt.Println(q)
	//	q("trantor.local", 1)
	//q("Bticino-Classe100X.local", 2)
	//q("perry.local", 3)
	//	q("perry.local", 6, dns.TypeCNAME)

	time.Sleep(2 * time.Second)

	go func() {
		for {
			//q("perry.local", 5, dns.TypeA, dns.TypeAAAA)
			q("_workstation._tcp.local", 6, dns.TypePTR)
			//q("myservice._workstation._tcp.local", 7, dns.TypeSRV)
			time.Sleep(1 * time.Second)
		}
	}()

	//	q("trantor.local", 99)

	time.Sleep(600 * time.Second)
}
