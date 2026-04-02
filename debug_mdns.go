//go:build ignore

package main

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

func main() {
	fmt.Println("=== Debug mDNS query ===")

	// Method 1: Multicast socket on port 5353
	fmt.Println("\n--- Method 1: Multicast listener on :5353 ---")
	testMulticast()

	// Method 2: Unicast QU from random port
	fmt.Println("\n--- Method 2: Unicast QU from random port ---")
	testUnicast()
}

func testMulticast() {
	// Try to bind to port 5353 with SO_REUSEPORT
	var conn net.PacketConn
	var err error

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

	conn, err = lc.ListenPacket(nil, "udp4", ":5353")
	if err != nil {
		fmt.Printf("Cannot bind :5353: %v\n", err)
		return
	}
	defer conn.Close()

	p := ipv4.NewPacketConn(conn)
	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251)}
	ifaces, _ := net.Interfaces()
	joined := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagMulticast != 0 {
			if err := p.JoinGroup(&iface, group); err == nil {
				fmt.Printf("Joined multicast on %s\n", iface.Name)
				joined++
			}
		}
	}
	fmt.Printf("Joined %d interfaces\n", joined)

	// Send query
	m := new(dns.Msg)
	m.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)
	m.RecursionDesired = false
	buf, _ := m.Pack()

	dst := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	n, err := conn.WriteTo(buf, dst)
	fmt.Printf("Sent %d bytes, err=%v\n", n, err)

	// Read responses
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	readBuf := make([]byte, 65535)
	count := 0
	for {
		n, addr, err := conn.ReadFrom(readBuf)
		if err != nil {
			fmt.Printf("Read ended: %v (got %d responses)\n", err, count)
			break
		}
		count++
		resp := new(dns.Msg)
		if err := resp.Unpack(readBuf[:n]); err == nil {
			fmt.Printf("  Response from %s: %d answer(s), %d extra(s)\n", addr, len(resp.Answer), len(resp.Extra))
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
	}
}

func testUnicast() {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		fmt.Printf("Cannot create unicast socket: %v\n", err)
		return
	}
	defer conn.Close()

	m := new(dns.Msg)
	m.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)
	m.RecursionDesired = false
	if len(m.Question) > 0 {
		m.Question[0].Qclass |= 1 << 15 // QU bit
	}
	buf, _ := m.Pack()

	dst := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	n, err := conn.WriteTo(buf, dst)
	fmt.Printf("Sent %d bytes (QU), err=%v\n", n, err)

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	readBuf := make([]byte, 65535)
	count := 0
	for {
		n, addr, err := conn.ReadFrom(readBuf)
		if err != nil {
			fmt.Printf("Read ended: %v (got %d responses)\n", err, count)
			break
		}
		count++
		resp := new(dns.Msg)
		if err := resp.Unpack(readBuf[:n]); err == nil {
			fmt.Printf("  Response from %s: %d answer(s), %d extra(s)\n", addr, len(resp.Answer), len(resp.Extra))
			for _, rr := range resp.Answer {
				fmt.Printf("    ANS: %s\n", rr.String())
			}
		}
	}
}
