//go:build ignore

package main

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

func main() {
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = 3 * time.Second

	// 1) Discover service types
	fmt.Println("=== Service types from local mDNSResponder ===")
	resp := query(c, "_services._dns-sd._udp.local.", dns.TypePTR)
	printResp(resp)

	// 2) Browse _http._tcp
	fmt.Println("\n=== _http._tcp instances ===")
	resp = query(c, "_http._tcp.local.", dns.TypePTR)
	printResp(resp)

	// Wait and retry to let mDNSResponder discover from network
	time.Sleep(2 * time.Second)

	fmt.Println("\n=== Service types (retry after 2s) ===")
	resp = query(c, "_services._dns-sd._udp.local.", dns.TypePTR)
	printResp(resp)

	fmt.Println("\n=== _http._tcp instances (retry) ===")
	resp = query(c, "_http._tcp.local.", dns.TypePTR)
	printResp(resp)

	// 3) Query ANY to get all records
	fmt.Println("\n=== ANY query for _http._tcp.local. ===")
	resp = query(c, "_http._tcp.local.", dns.TypeANY)
	printResp(resp)

	// Try SRV, TXT for any found instances
	if resp != nil {
		for _, rr := range resp.Answer {
			if ptr, ok := rr.(*dns.PTR); ok {
				fmt.Printf("\n=== SRV for %s ===\n", ptr.Ptr)
				r := query(c, ptr.Ptr, dns.TypeSRV)
				printResp(r)

				fmt.Printf("\n=== TXT for %s ===\n", ptr.Ptr)
				r = query(c, ptr.Ptr, dns.TypeTXT)
				printResp(r)

				if r != nil {
					for _, rr2 := range append(r.Answer, r.Extra...) {
						if srv, ok := rr2.(*dns.SRV); ok {
							fmt.Printf("\n=== A for %s ===\n", srv.Target)
							r2 := query(c, srv.Target, dns.TypeA)
							printResp(r2)
							fmt.Printf("\n=== AAAA for %s ===\n", srv.Target)
							r2 = query(c, srv.Target, dns.TypeAAAA)
							printResp(r2)
						}
					}
				}
			}
		}
	}
}

func query(c *dns.Client, name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = false
	resp, _, err := c.Exchange(m, "127.0.0.1:5353")
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		return nil
	}
	return resp
}

func printResp(resp *dns.Msg) {
	if resp == nil {
		fmt.Println("  (nil response)")
		return
	}
	fmt.Printf("  Answers: %d, Extra: %d\n", len(resp.Answer), len(resp.Extra))
	for _, rr := range resp.Answer {
		fmt.Printf("    ANS: %s\n", rr.String())
	}
	for _, rr := range resp.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			continue
		}
		fmt.Printf("    EXT: %s\n", rr.String())
	}
}
