package output

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"test/internal/scanner"
)

func PrintText(results map[string]*scanner.HostResult) {
	ips := sortedKeys(results)

	for i, ip := range ips {
		host := results[ip]

		fmt.Printf("Target: %s\n", ip)
		fmt.Println(strings.Repeat("─", 60))

		fmt.Println("services:")
		for _, svc := range host.Services {
			if svc.Port > 0 {
				fmt.Printf("  %d/%s %s:\n", svc.Port, svc.Protocol, svc.ServiceType)
			} else {
				fmt.Printf("  %s:\n", svc.ServiceType)
			}
			fmt.Printf("    Name=%s\n", svc.Name)
			if svc.IPv4 != "" {
				fmt.Printf("    IPv4=%s\n", svc.IPv4)
			}
			if svc.IPv6 != "" {
				fmt.Printf("    IPv6=%s\n", svc.IPv6)
			}
			if svc.Hostname != "" {
				fmt.Printf("    Hostname=%s\n", svc.Hostname)
			}
			fmt.Printf("    TTL=%d\n", svc.TTL)

			// Deep banner: TXT record fields
			for _, txt := range svc.TXTRecords {
				if txt != "" {
					fmt.Printf("    %s\n", txt)
				}
			}
		}

		if len(host.PTRRecords) > 0 {
			fmt.Println("  answers:")
			fmt.Println("    PTR:")
			for _, ptr := range host.PTRRecords {
				fmt.Printf("      %s\n", ptr)
			}
		}

		if i < len(ips)-1 {
			fmt.Println()
		}
	}
}

func PrintJSON(results map[string]*scanner.HostResult) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

func sortedKeys(m map[string]*scanner.HostResult) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
