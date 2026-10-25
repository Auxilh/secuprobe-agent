// Package targets turns the SCAN_TARGETS setting into a bounded list of hosts.
package targets

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// MaxHosts bounds a single scan (a /22). Larger networks are split across several agents.
const MaxHosts = 1024

// Parse accepts a comma or whitespace separated list of IPv4/IPv6 addresses,
// IPv4 CIDR ranges and hostnames. Duplicates are removed, order is preserved.
func Parse(spec string) ([]string, error) {
	fields := strings.FieldsFunc(spec, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == ';'
	})
	if len(fields) == 0 {
		return nil, fmt.Errorf("no scan target given")
	}

	seen := map[string]bool{}
	var hosts []string
	add := func(h string) error {
		if seen[h] {
			return nil
		}
		if len(hosts) >= MaxHosts {
			return fmt.Errorf("too many hosts: the limit is %d per agent (a /22)", MaxHosts)
		}
		seen[h] = true
		hosts = append(hosts, h)
		return nil
	}

	for _, f := range fields {
		switch {
		case strings.Contains(f, "/"):
			prefix, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR range %q", f)
			}
			if !prefix.Addr().Is4() {
				return nil, fmt.Errorf("IPv6 ranges are not supported (%q): list the addresses instead", f)
			}
			if prefix.Bits() < 22 {
				return nil, fmt.Errorf("range %q is too large: the limit is a /22 (%d hosts)", f, MaxHosts)
			}
			for _, a := range expand(prefix.Masked()) {
				if err := add(a); err != nil {
					return nil, err
				}
			}
		default:
			if addr, err := netip.ParseAddr(f); err == nil {
				if err := add(addr.String()); err != nil {
					return nil, err
				}
				continue
			}
			if !validHostname(f) {
				return nil, fmt.Errorf("invalid target %q", f)
			}
			if err := add(strings.ToLower(f)); err != nil {
				return nil, err
			}
		}
	}
	return hosts, nil
}

// expand lists the usable addresses of an IPv4 prefix (network and broadcast
// addresses are skipped, except for /31 and /32).
func expand(p netip.Prefix) []string {
	var out []string
	first := p.Addr()
	size := 1 << (32 - p.Bits())
	a := first
	for i := 0; i < size; i++ {
		if size > 2 && (i == 0 || i == size-1) {
			a = a.Next()
			continue
		}
		out = append(out, a.String())
		a = a.Next()
	}
	return out
}

func validHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, r := range label {
			ok := r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !ok || (r == '-' && (i == 0 || i == len(label)-1)) {
				return false
			}
		}
	}
	return true
}

// LocalDefault returns the primary non-loopback IPv4 address of this machine,
// used when no target is configured: the agent then scans its own host as seen
// from the network (services bound to 127.0.0.1 only are not network-exposed).
func LocalDefault() string {
	conn, err := net.Dial("udp", "192.0.2.1:9") // no packet is sent for UDP "dial"
	if err == nil {
		defer conn.Close()
		if a, ok := conn.LocalAddr().(*net.UDPAddr); ok && a.IP.To4() != nil && !a.IP.IsLoopback() {
			return a.IP.String()
		}
	}
	return "127.0.0.1"
}
