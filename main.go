package main

import (
	"context"
	"fmt"
	"log"
	"time"
)

func main() {

	client, err := newmDNSClient()
	if err != nil {
		log.Fatal(err)
	}

	q := func(domain string, id int) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		answers, err := client.query(ctx, domain)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(id, answers)
	}
	fmt.Println(q)
	//	q("trantor.local", 1)
	//q("Bticino-Classe100X.local", 2)
	//q("perry.local", 3)
	q("esphome.local", 5)
	time.Sleep(2 * time.Second)

	//	q("trantor.local", 99)

	time.Sleep(60 * time.Second)
}
