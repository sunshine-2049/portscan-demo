//go:build ignore

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

func main() {
	fmt.Println("=== Debug: Multicast via explicit en0 binding ===")

	iface, _ := net.InterfaceByName("en0")

	conn, err := net.ListenPacket("udp4", "192.168.3.90:0")
	if err != nil {
		fmt.Printf("Bind to 192.168.3.90 failed: %v\n", err)
		return
	}
	defer conn.Close()
	fmt.Printf("Bound to %s\n", conn.LocalAddr())

	p := ipv4.NewPacketConn(conn)
	p.SetMulticastInterface(iface)
	p.SetMulticastTTL(255)
	p.SetMulticastLoopback(true)

	m := new(dns.Msg)
	m.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)
	m.RecursionDesired = false
	buf, _ := m.Pack()

	dst := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	n, err := conn.WriteTo(buf, dst)
	fmt.Printf("Sent %d bytes, err=%v\n", n, err)

	time.AfterFunc(300*time.Millisecond, func() {
		conn.WriteTo(buf, dst)
	})

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	readBuf := make([]byte, 65535)
	count := 0
	for {
		rn, addr, err := conn.ReadFrom(readBuf)
		if err != nil {
			fmt.Printf("Read ended: %v (got %d)\n", err, count)
			break
		}
		count++
		resp := new(dns.Msg)
		if err := resp.Unpack(readBuf[:rn]); err == nil {
			fmt.Printf("[%d] from %s: A=%d E=%d\n", count, addr, len(resp.Answer), len(resp.Extra))
			for _, rr := range resp.Answer {
				fmt.Printf("  %s\n", rr.String())
			}
		}
	}
	fmt.Printf("Total: %d\n", count)
}
