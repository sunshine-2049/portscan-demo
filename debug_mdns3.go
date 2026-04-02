//go:build ignore

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

func main() {
	fmt.Println("=== Debug mDNS v3: ListenMulticastUDP ===")

	iface, err := net.InterfaceByName("en0")
	if err != nil {
		fmt.Printf("en0 error: %v\n", err)
		return
	}

	maddr := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	conn, err := net.ListenMulticastUDP("udp4", iface, maddr)
	if err != nil {
		fmt.Printf("ListenMulticastUDP error: %v\n", err)
		return
	}
	defer conn.Close()

	fmt.Println("Listening on multicast 224.0.0.251:5353 via en0")

	// Send query from a SEPARATE unicast socket
	uconn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		fmt.Printf("Unicast socket error: %v\n", err)
		return
	}
	defer uconn.Close()

	m := new(dns.Msg)
	m.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)
	m.RecursionDesired = false
	buf, _ := m.Pack()

	dst := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	n, err := uconn.WriteTo(buf, dst)
	fmt.Printf("Sent %d bytes via unicast socket, err=%v\n", n, err)

	time.AfterFunc(500*time.Millisecond, func() {
		uconn.WriteTo(buf, dst)
		fmt.Println("Resent query")
	})

	// Read from multicast socket
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	readBuf := make([]byte, 65535)
	count := 0
	for {
		rn, addr, err := conn.ReadFromUDP(readBuf)
		if err != nil {
			fmt.Printf("Read ended: %v (got %d messages)\n", err, count)
			break
		}
		count++
		resp := new(dns.Msg)
		if err := resp.Unpack(readBuf[:rn]); err == nil {
			fmt.Printf("[%d] from %s: Q=%d A=%d NS=%d E=%d\n",
				count, addr, len(resp.Question), len(resp.Answer), len(resp.Ns), len(resp.Extra))
			for _, rr := range resp.Answer {
				fmt.Printf("  A: %s\n", rr.String())
			}
		}
	}
	fmt.Printf("Total: %d messages\n", count)
}
