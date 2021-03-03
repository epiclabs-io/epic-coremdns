package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
)

func main() {

	client, err := newmDNSClient()
	if err != nil {
		log.Fatal(err)
	}

	q := func(domain string, id int, recordType uint16) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		answers, err := client.query(ctx, domain, recordType)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(id, answers)
	}
	fmt.Println(q)
	//	q("trantor.local", 1)
	//q("Bticino-Classe100X.local", 2)
	//q("perry.local", 3)
	q("esphometest.local", 5, dns.TypeA)
	time.Sleep(2 * time.Second)

	go func() {
		for {
			q("_workstation._tcp.local", 6, dns.TypePTR)
			time.Sleep(1 * time.Second)
		}
	}()

	//	q("trantor.local", 99)

	time.Sleep(60 * time.Second)
}
