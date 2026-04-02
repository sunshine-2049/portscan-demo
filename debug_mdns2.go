//go:build ignore

package main

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

func main() {
	fmt.Println("=== Debug mDNS v2 ===")

	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var opErr error
			c.Control(func(fd uintptr) {
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if opErr == nil {
					opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
				}
			})
			return opErr
		},
	}

	conn, err := lc.ListenPacket(context.Background(), "udp4", ":5353")
	if err != nil {
		fmt.Printf("Cannot bind :5353: %v\n", err)
		return
	}
	defer conn.Close()

	p := ipv4.NewPacketConn(conn)
	p.SetMulticastLoopback(true)

	group := net.IPv4(224, 0, 0, 251)

	// Only join on en0 (the primary interface)
	iface, err := net.InterfaceByName("en0")
	if err != nil {
		fmt.Printf("Cannot get en0: %v\n", err)
		return
	}
	if err := p.JoinGroup(iface, &net.UDPAddr{IP: group}); err != nil {
		fmt.Printf("JoinGroup on en0 failed: %v\n", err)
	} else {
		fmt.Println("Joined multicast on en0")
	}
	p.SetMulticastInterface(iface)
	p.SetMulticastTTL(255)

	// Send PTR query
	m := new(dns.Msg)
	m.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)
	m.RecursionDesired = false
	buf, _ := m.Pack()

	dst := &net.UDPAddr{IP: group, Port: 5353}
	n, err := conn.WriteTo(buf, dst)
	fmt.Printf("Sent %d bytes, err=%v\n", n, err)

	// Resend after 200ms
	time.AfterFunc(200*time.Millisecond, func() {
		conn.WriteTo(buf, dst)
		fmt.Println("Resent query")
	})

	// Read
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	readBuf := make([]byte, 65535)
	count := 0
	for {
		rn, addr, err := conn.ReadFrom(readBuf)
		if err != nil {
			fmt.Printf("Read ended: %v (got %d messages)\n", err, count)
			break
		}
		count++
		resp := new(dns.Msg)
		if err := resp.Unpack(readBuf[:rn]); err == nil {
			fmt.Printf("[%d] from %s: questions=%d answers=%d extra=%d\n",
				count, addr, len(resp.Question), len(resp.Answer), len(resp.Extra))
			for _, q := range resp.Question {
				fmt.Printf("  Q: %s %s\n", q.Name, dns.TypeToString[q.Qtype])
			}
			for _, rr := range resp.Answer {
				fmt.Printf("  A: %s\n", rr.String())
			}
			for _, rr := range resp.Extra {
				if _, ok := rr.(*dns.OPT); ok {
					continue
				}
				fmt.Printf("  E: %s\n", rr.String())
			}
		} else {
			fmt.Printf("[%d] from %s: unpack error: %v\n", count, addr, err)
		}
	}
	fmt.Printf("\n=== Total: %d messages ===\n", count)
}
