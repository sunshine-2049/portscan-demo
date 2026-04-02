//go:build ignore

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

func main() {
	fmt.Println("=== Debug: direct DNS client to mDNS address ===")

	// Use dns.Client to send a standard DNS query to the mDNS multicast address
	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = 5 * time.Second

	m := new(dns.Msg)
	m.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)
	m.RecursionDesired = false

	resp, rtt, err := c.Exchange(m, "224.0.0.251:5353")
	fmt.Printf("Exchange: err=%v, rtt=%v\n", err, rtt)
	if resp != nil {
		fmt.Printf("Response: answers=%d extra=%d\n", len(resp.Answer), len(resp.Extra))
		for _, rr := range resp.Answer {
			fmt.Printf("  A: %s\n", rr.String())
		}
	}

	fmt.Println("\n--- Also try direct to localhost mDNS ---")
	resp2, rtt2, err2 := c.Exchange(m, "127.0.0.1:5353")
	fmt.Printf("Exchange(localhost): err=%v, rtt=%v\n", err2, rtt2)
	if resp2 != nil {
		fmt.Printf("Response: answers=%d extra=%d\n", len(resp2.Answer), len(resp2.Extra))
		for _, rr := range resp2.Answer {
			fmt.Printf("  A: %s\n", rr.String())
		}
	}

	fmt.Println("\n--- Try specific service type ---")
	m3 := new(dns.Msg)
	m3.SetQuestion("_http._tcp.local.", dns.TypePTR)
	m3.RecursionDesired = false
	resp3, rtt3, err3 := c.Exchange(m3, "224.0.0.251:5353")
	fmt.Printf("Exchange(_http._tcp): err=%v, rtt=%v\n", err3, rtt3)
	if resp3 != nil {
		fmt.Printf("Response: answers=%d extra=%d\n", len(resp3.Answer), len(resp3.Extra))
		for _, rr := range resp3.Answer {
			fmt.Printf("  A: %s\n", rr.String())
		}
	}

	// Also try getting the local machine's hostname via mDNS
	hostname, _ := net.LookupAddr("192.168.3.90")
	fmt.Printf("\nReverse lookup 192.168.3.90: %v\n", hostname)
}
