package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"test/internal/network"
	"test/internal/output"
	"test/internal/scanner"

	"github.com/spf13/cobra"
)

var (
	cidr      string
	ports     string
	timeout   int
	jsonOut   bool
	ifaceName string
)

var rootCmd = &cobra.Command{
	Use:   "mdns-scanner",
	Short: "mDNS/DNS-SD network asset discovery tool",
	Long: `A CLI tool for discovering mDNS/DNS-SD services on a local network.
Scans the specified IP range and port range, identifies services,
and provides deep banner identification including TXT record metadata.

Example:
  mdns-scanner -c 192.168.3.0/24 -p 1-65535
  mdns-scanner -c 192.168.1.0/24 -p 80,443,445,548 -t 20
  mdns-scanner -c 192.168.3.107 -j`,
	RunE: runScan,
}

func runScan(cmd *cobra.Command, args []string) error {
	ipRange, err := network.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	portRange, err := network.ParsePortRange(ports)
	if err != nil {
		return fmt.Errorf("invalid port range: %w", err)
	}

	var iface *net.Interface
	if ifaceName != "" {
		iface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			return fmt.Errorf("invalid interface %q: %w", ifaceName, err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	fmt.Fprintf(os.Stderr, "[*] mDNS Scanner starting...\n")
	fmt.Fprintf(os.Stderr, "[*] Target: %s  Ports: %s  Timeout: %ds\n", cidr, ports, timeout)

	s := scanner.New(iface)
	results, err := s.Scan(ctx, ipRange, portRange)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if len(results) == 0 {
		fmt.Fprintf(os.Stderr, "[!] No mDNS services discovered in the specified range.\n")
		return nil
	}

	totalServices := 0
	for _, host := range results {
		totalServices += len(host.Services)
	}
	fmt.Fprintf(os.Stderr, "[+] Discovered %d host(s), %d service(s).\n\n", len(results), totalServices)

	if jsonOut {
		output.PrintJSON(results)
	} else {
		output.PrintText(results)
	}
	return nil
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&cidr, "cidr", "c", "", "Target IP range in CIDR notation (e.g., 192.168.3.0/24)")
	rootCmd.Flags().StringVarP(&ports, "ports", "p", "1-65535", "Port range to filter (e.g., 1-1024, 80,443,8080)")
	rootCmd.Flags().IntVarP(&timeout, "timeout", "t", 15, "Scan timeout in seconds")
	rootCmd.Flags().BoolVarP(&jsonOut, "json", "j", false, "Output results in JSON format")
	rootCmd.Flags().StringVarP(&ifaceName, "interface", "i", "", "Network interface to use (e.g., en0)")
	rootCmd.MarkFlagRequired("cidr")
}
