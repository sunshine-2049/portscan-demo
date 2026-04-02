package network

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type IPRange struct {
	Network *net.IPNet
}

type PortRange struct {
	ranges []portInterval
}

type portInterval struct {
	Start int
	End   int
}

func ParseCIDR(cidr string) (*IPRange, error) {
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return &IPRange{Network: network}, nil
}

func (r *IPRange) Contains(ip net.IP) bool {
	return r.Network.Contains(ip)
}

// ParsePortRange parses port specifications like "1-1024", "80,443", "1-1024,8080,8443"
func ParsePortRange(portStr string) (*PortRange, error) {
	pr := &PortRange{}

	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", rangeParts[1])
			}
			if start > end || start < 0 || end > 65535 {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}
			pr.ranges = append(pr.ranges, portInterval{Start: start, End: end})
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if port < 0 || port > 65535 {
				return nil, fmt.Errorf("invalid port: %d", port)
			}
			pr.ranges = append(pr.ranges, portInterval{Start: port, End: port})
		}
	}

	if len(pr.ranges) == 0 {
		return nil, fmt.Errorf("no valid ports specified")
	}

	return pr, nil
}

func (pr *PortRange) Contains(port int) bool {
	for _, r := range pr.ranges {
		if port >= r.Start && port <= r.End {
			return true
		}
	}
	return false
}
