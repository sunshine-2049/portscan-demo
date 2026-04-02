package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"test/internal/network"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
)

var defaultServiceTypes = []string{
	"_http._tcp",
	"_https._tcp",
	"_workstation._tcp",
	"_smb._tcp",
	"_afpovertcp._tcp",
	"_ssh._tcp",
	"_sftp-ssh._tcp",
	"_ftp._tcp",
	"_nfs._tcp",
	"_ipp._tcp",
	"_ipps._tcp",
	"_printer._tcp",
	"_pdl-datastream._tcp",
	"_device-info._tcp",
	"_raop._tcp",
	"_airplay._tcp",
	"_googlecast._tcp",
	"_hap._tcp",
	"_homekit._tcp",
	"_qdiscover._tcp",
	"_rfb._tcp",
	"_daap._tcp",
	"_telnet._tcp",
	"_scanner._tcp",
	"_companion-link._tcp",
	"_sleep-proxy._udp",
	"_mqtt._tcp",
	"_rdp._tcp",
	"_mysql._tcp",
	"_postgresql._tcp",
	"_mongodb._tcp",
	"_redis._tcp",
	"_elasticsearch._tcp",
	"_amqp._tcp",
	"_rtsp._tcp",
	"_sip._tcp",
	"_sip._udp",
	"_xmpp-client._tcp",
	"_xmpp-server._tcp",
	"_adisk._tcp",
	"_mediaremotetv._tcp",
	"_touch-able._tcp",
	"_coap._udp",
	"_ntp._udp",
}

type ServiceInfo struct {
	ServiceType string            `json:"service_type"`
	Name        string            `json:"name"`
	Port        int               `json:"port"`
	Protocol    string            `json:"protocol"`
	IPv4        string            `json:"ipv4,omitempty"`
	IPv6        string            `json:"ipv6,omitempty"`
	Hostname    string            `json:"hostname"`
	TTL         uint32            `json:"ttl"`
	TXTRecords  []string          `json:"txt_records,omitempty"`
	TXTMap      map[string]string `json:"txt_map,omitempty"`
}

type HostResult struct {
	IP         string        `json:"ip"`
	Services   []ServiceInfo `json:"services"`
	PTRRecords []string      `json:"ptr_records"`
}

type Scanner struct {
	serviceTypes []string
	iface        *net.Interface
}

func New(iface *net.Interface) *Scanner {
	return &Scanner{
		serviceTypes: defaultServiceTypes,
		iface:        iface,
	}
}

var mdnsDst = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

func (s *Scanner) Scan(ctx context.Context, ipRange *network.IPRange, portRange *network.PortRange) (map[string]*HostResult, error) {
	mcastConn, ucastConn, err := s.createConnections()
	if err != nil {
		return nil, fmt.Errorf("failed to create mDNS sockets: %w", err)
	}
	defer mcastConn.Close()
	defer ucastConn.Close()

	var allResponses []*dns.Msg
	var mu sync.Mutex
	collectCtx, collectCancel := context.WithCancel(ctx)

	handler := func(msg *dns.Msg) {
		mu.Lock()
		allResponses = append(allResponses, msg)
		mu.Unlock()
	}

	var collectWg sync.WaitGroup
	collectWg.Add(2)
	go func() { defer collectWg.Done(); readLoop(collectCtx, mcastConn, handler) }()
	go func() { defer collectWg.Done(); readLoop(collectCtx, ucastConn, handler) }()

	// Phase 1: Discover service types via meta-query
	sendMDNS(ucastConn, "_services._dns-sd._udp.local.", dns.TypePTR, true)
	sendMDNS(mcastConn, "_services._dns-sd._udp.local.", dns.TypePTR, false)
	sleepCtx(ctx, 2*time.Second)

	mu.Lock()
	metaTypes := extractServiceTypes(allResponses)
	mu.Unlock()
	serviceTypes := mergeTypes(s.serviceTypes, metaTypes)

	fmt.Fprintf(os.Stderr, "[*] Probing %d service types...\n", len(serviceTypes))

	// Phase 2: PTR queries for all service types
	for _, st := range serviceTypes {
		fqdn := st + ".local."
		sendMDNS(ucastConn, fqdn, dns.TypePTR, true)
		sendMDNS(mcastConn, fqdn, dns.TypePTR, false)
	}
	sleepCtx(ctx, 2*time.Second)

	// Resend once for reliability
	for _, st := range serviceTypes {
		sendMDNS(ucastConn, st+".local.", dns.TypePTR, true)
	}
	sleepCtx(ctx, 1*time.Second)

	// Phase 3: SRV + TXT for discovered instances
	mu.Lock()
	instances := extractInstances(allResponses, serviceTypes)
	mu.Unlock()

	for fqdn := range instances {
		sendMDNS(ucastConn, fqdn, dns.TypeSRV, true)
		sendMDNS(ucastConn, fqdn, dns.TypeTXT, true)
		sendMDNS(mcastConn, fqdn, dns.TypeSRV, false)
		sendMDNS(mcastConn, fqdn, dns.TypeTXT, false)
	}
	sleepCtx(ctx, 2*time.Second)

	// Phase 4: Resolve A/AAAA for discovered hostnames
	mu.Lock()
	hostnames := extractHostnames(allResponses)
	mu.Unlock()

	for h := range hostnames {
		sendMDNS(ucastConn, h, dns.TypeA, true)
		sendMDNS(ucastConn, h, dns.TypeAAAA, true)
		sendMDNS(mcastConn, h, dns.TypeA, false)
		sendMDNS(mcastConn, h, dns.TypeAAAA, false)
	}

	// Wait for remaining context time
	remaining := contextRemaining(ctx)
	if remaining > 3*time.Second {
		remaining = 3 * time.Second
	}
	if remaining > 0 {
		sleepCtx(ctx, remaining)
	}

	collectCancel()
	collectWg.Wait()

	mu.Lock()
	defer mu.Unlock()
	return buildResults(allResponses, serviceTypes, ipRange, portRange), nil
}

func (s *Scanner) createConnections() (mcast, ucast net.PacketConn, err error) {
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

	mcast, err = lc.ListenPacket(context.Background(), "udp4", ":5353")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Cannot bind to port 5353 (%v), using unicast-only mode\n", err)
		mcast, err = net.ListenPacket("udp4", ":0")
		if err != nil {
			return nil, nil, fmt.Errorf("multicast socket: %w", err)
		}
	} else {
		p := ipv4.NewPacketConn(mcast)
		group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251)}
		if s.iface != nil {
			_ = p.JoinGroup(s.iface, group)
		} else {
			ifaces, _ := net.Interfaces()
			for _, iface := range ifaces {
				if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagMulticast != 0 {
					_ = p.JoinGroup(&iface, group)
				}
			}
		}
	}

	ucast, err = net.ListenPacket("udp4", ":0")
	if err != nil {
		mcast.Close()
		return nil, nil, fmt.Errorf("unicast socket: %w", err)
	}
	return mcast, ucast, nil
}

func sendMDNS(conn net.PacketConn, name string, qtype uint16, unicast bool) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = false
	if unicast && len(m.Question) > 0 {
		m.Question[0].Qclass |= 1 << 15 // QU bit
	}
	if buf, err := m.Pack(); err == nil {
		conn.WriteTo(buf, mdnsDst)
	}
}

func readLoop(ctx context.Context, conn net.PacketConn, handler func(*dns.Msg)) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err == nil {
			handler(msg)
		}
	}
}

func extractServiceTypes(msgs []*dns.Msg) []string {
	seen := make(map[string]bool)
	var types []string
	for _, msg := range msgs {
		for _, rr := range flattenRRs(msg) {
			ptr, ok := rr.(*dns.PTR)
			if !ok {
				continue
			}
			if !strings.HasSuffix(ptr.Hdr.Name, "_dns-sd._udp.local.") {
				continue
			}
			svcType := strings.TrimSuffix(ptr.Ptr, ".local.")
			if !seen[svcType] && strings.HasPrefix(svcType, "_") {
				seen[svcType] = true
				types = append(types, svcType)
			}
		}
	}
	return types
}

func extractInstances(msgs []*dns.Msg, serviceTypes []string) map[string]string {
	stSet := make(map[string]bool)
	for _, st := range serviceTypes {
		stSet[st+".local."] = true
	}

	instances := make(map[string]string) // instanceFQDN -> serviceType
	for _, msg := range msgs {
		for _, rr := range flattenRRs(msg) {
			ptr, ok := rr.(*dns.PTR)
			if !ok {
				continue
			}
			if stSet[ptr.Hdr.Name] {
				instances[ptr.Ptr] = strings.TrimSuffix(ptr.Hdr.Name, ".local.")
			}
		}
	}
	return instances
}

func extractHostnames(msgs []*dns.Msg) map[string]bool {
	hostnames := make(map[string]bool)
	for _, msg := range msgs {
		for _, rr := range flattenRRs(msg) {
			if srv, ok := rr.(*dns.SRV); ok {
				hostnames[srv.Target] = true
			}
		}
	}
	return hostnames
}

type instanceData struct {
	name     string
	svcType  string
	hostname string
	port     int
	ttl      uint32
	ipv4     []net.IP
	ipv6     []net.IP
	txt      []string
}

func buildResults(msgs []*dns.Msg, serviceTypes []string, ipRange *network.IPRange, portRange *network.PortRange) map[string]*HostResult {
	stSet := make(map[string]bool)
	for _, st := range serviceTypes {
		stSet[st+".local."] = true
	}

	// Step 1: Collect PTR -> instance mapping
	instanceSvcMap := make(map[string]string) // instanceFQDN -> serviceType FQDN
	for _, msg := range msgs {
		for _, rr := range flattenRRs(msg) {
			if ptr, ok := rr.(*dns.PTR); ok && stSet[ptr.Hdr.Name] {
				instanceSvcMap[ptr.Ptr] = ptr.Hdr.Name
			}
		}
	}

	// Step 2: Collect SRV, TXT, A, AAAA records
	srvMap := make(map[string]*dns.SRV)
	txtMap := make(map[string][]string)
	aMap := make(map[string][]net.IP)    // hostname -> IPv4
	aaaaMap := make(map[string][]net.IP) // hostname -> IPv6

	for _, msg := range msgs {
		for _, rr := range flattenRRs(msg) {
			switch r := rr.(type) {
			case *dns.SRV:
				if _, ok := instanceSvcMap[r.Hdr.Name]; ok {
					srvMap[r.Hdr.Name] = r
				}
			case *dns.TXT:
				if _, ok := instanceSvcMap[r.Hdr.Name]; ok {
					txtMap[r.Hdr.Name] = dedup(append(txtMap[r.Hdr.Name], r.Txt...))
				}
			case *dns.A:
				aMap[r.Hdr.Name] = appendUniqueIP(aMap[r.Hdr.Name], r.A)
			case *dns.AAAA:
				aaaaMap[r.Hdr.Name] = appendUniqueIP(aaaaMap[r.Hdr.Name], r.AAAA)
			}
		}
	}

	// Step 3: Assemble instances
	instances := make(map[string]*instanceData)
	for instanceFQDN, svcFQDN := range instanceSvcMap {
		svcType := strings.TrimSuffix(svcFQDN, ".local.")
		name := extractInstanceName(instanceFQDN, svcType)

		d := &instanceData{
			name:    name,
			svcType: svcType,
		}

		if srv, ok := srvMap[instanceFQDN]; ok {
			d.hostname = strings.TrimSuffix(srv.Target, ".")
			d.port = int(srv.Port)
			d.ttl = srv.Hdr.Ttl
		}

		d.txt = txtMap[instanceFQDN]

		if d.hostname != "" {
			hostFQDN := d.hostname + "."
			d.ipv4 = aMap[hostFQDN]
			d.ipv6 = aaaaMap[hostFQDN]
		}

		instances[instanceFQDN] = d
	}

	// Step 4: Filter and build results
	results := make(map[string]*HostResult)
	for _, d := range instances {
		protocol := "tcp"
		if strings.Contains(d.svcType, "._udp") {
			protocol = "udp"
		}
		svcName := strings.TrimPrefix(d.svcType, "_")
		if idx := strings.Index(svcName, "._"); idx != -1 {
			svcName = svcName[:idx]
		}

		txtKVMap := make(map[string]string)
		for _, t := range d.txt {
			parts := strings.SplitN(t, "=", 2)
			if len(parts) == 2 {
				txtKVMap[parts[0]] = parts[1]
			}
		}

		for _, ip := range d.ipv4 {
			if !ipRange.Contains(ip) {
				continue
			}
			if d.port > 0 && !portRange.Contains(d.port) {
				continue
			}

			ipStr := ip.String()
			svc := ServiceInfo{
				ServiceType: svcName,
				Name:        d.name,
				Port:        d.port,
				Protocol:    protocol,
				IPv4:        ipStr,
				Hostname:    d.hostname,
				TTL:         d.ttl,
				TXTRecords:  d.txt,
				TXTMap:      txtKVMap,
			}
			if len(d.ipv6) > 0 {
				svc.IPv6 = d.ipv6[0].String()
			}

			if results[ipStr] == nil {
				results[ipStr] = &HostResult{IP: ipStr}
			}
			results[ipStr].Services = append(results[ipStr].Services, svc)

			ptrRecord := d.svcType + ".local"
			if !containsStr(results[ipStr].PTRRecords, ptrRecord) {
				results[ipStr].PTRRecords = append(results[ipStr].PTRRecords, ptrRecord)
			}
		}

		// Also match if only IPv6 found and no IPv4
		if len(d.ipv4) == 0 && len(d.ipv6) > 0 {
			for _, ip6 := range d.ipv6 {
				ipStr := ip6.String()
				svc := ServiceInfo{
					ServiceType: svcName,
					Name:        d.name,
					Port:        d.port,
					Protocol:    protocol,
					IPv6:        ipStr,
					Hostname:    d.hostname,
					TTL:         d.ttl,
					TXTRecords:  d.txt,
					TXTMap:      txtKVMap,
				}
				if results[ipStr] == nil {
					results[ipStr] = &HostResult{IP: ipStr}
				}
				results[ipStr].Services = append(results[ipStr].Services, svc)

				ptrRecord := d.svcType + ".local"
				if !containsStr(results[ipStr].PTRRecords, ptrRecord) {
					results[ipStr].PTRRecords = append(results[ipStr].PTRRecords, ptrRecord)
				}
			}
		}
	}

	return results
}

func flattenRRs(msg *dns.Msg) []dns.RR {
	rrs := make([]dns.RR, 0, len(msg.Answer)+len(msg.Ns)+len(msg.Extra))
	rrs = append(rrs, msg.Answer...)
	rrs = append(rrs, msg.Ns...)
	rrs = append(rrs, msg.Extra...)
	return rrs
}

func extractInstanceName(fqdn, serviceType string) string {
	suffix := "." + serviceType + ".local."
	name := strings.TrimSuffix(fqdn, suffix)
	name = strings.ReplaceAll(name, "\\032", " ")
	return name
}

func appendUniqueIP(ips []net.IP, ip net.IP) []net.IP {
	for _, existing := range ips {
		if existing.Equal(ip) {
			return ips
		}
	}
	return append(ips, ip)
}

func dedup(ss []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func mergeTypes(base, extra []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, t := range base {
		t = strings.TrimSpace(t)
		if t != "" && !seen[t] {
			seen[t] = true
			result = append(result, t)
		}
	}
	for _, t := range extra {
		t = strings.TrimSpace(t)
		if t != "" && !seen[t] {
			seen[t] = true
			result = append(result, t)
		}
	}
	return result
}

func containsStr(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func contextRemaining(ctx context.Context) time.Duration {
	if d, ok := ctx.Deadline(); ok {
		return time.Until(d)
	}
	return 0
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}
