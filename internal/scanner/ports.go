package scanner

import (
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Top 1000 most common ports (subset — key services)
var TOP_1000_PORTS = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 111, 119, 135, 139, 143, 179, 194,
	443, 445, 465, 500, 513, 514, 515, 587, 631, 993, 995, 1080, 1194,
	1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
	3000, 3128, 3306, 3389, 3690, 4333, 4444, 4567, 4848, 5000,
	5432, 5900, 5901, 5984, 6379, 6443, 6667, 7001, 7002, 7070,
	8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200,
	9300, 9418, 10000, 11211, 27017, 27018, 28017, 50000, 50070,
}

// OpenPort holds information about an open TCP port.
type OpenPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Banner   string `json:"banner,omitempty"`
}

// Port states (audit F39). Only "closed" (explicit refusal) proves that a port
// previously reported open has been closed; "filtered" (no answer before the
// timeout) and "unreachable" (network or local error) prove nothing.
const (
	StateOpen        = "open"
	StateClosed      = "closed"
	StateFiltered    = "filtered"
	StateUnreachable = "unreachable"
)

// PortState is the outcome of a TCP connect on one port.
type PortState struct {
	Port   int    `json:"port"`
	State  string `json:"state"`
	Banner string `json:"banner,omitempty"`
}

// classifyDialError maps a dial error to a port state.
func classifyDialError(err error) string {
	// syscall.ECONNREFUSED on Unix; Windows reports WSAECONNREFUSED ("actively refused").
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "refused") {
		return StateClosed
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateFiltered
	}
	return StateUnreachable
}

// ScanPortStates performs a concurrent TCP connect on every port and returns
// the state of each one, sorted by port.
func ScanPortStates(host string, ports []int, timeout time.Duration, concurrency int) []PortState {
	if concurrency <= 0 {
		concurrency = 100
	}

	jobs := make(chan int, len(ports))
	results := make(chan PortState, len(ports))

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				address := net.JoinHostPort(host, strconv.Itoa(port))
				conn, err := net.DialTimeout("tcp", address, timeout)
				if err != nil {
					results <- PortState{Port: port, State: classifyDialError(err)}
					continue
				}
				banner := grabBanner(conn, timeout)
				conn.Close()
				results <- PortState{Port: port, State: StateOpen, Banner: banner}
			}
		}()
	}

	for _, p := range ports {
		jobs <- p
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var states []PortState
	for r := range results {
		states = append(states, r)
	}
	sort.Slice(states, func(i, j int) bool { return states[i].Port < states[j].Port })
	return states
}

// OpenPorts keeps the open ports of a state list (report format accepted by
// every server version).
func OpenPorts(states []PortState) []OpenPort {
	var open []OpenPort
	for _, s := range states {
		if s.State == StateOpen {
			open = append(open, OpenPort{Port: s.Port, Protocol: "tcp", Banner: s.Banner})
		}
	}
	return open
}

// ScanPorts performs a concurrent TCP port scan on the given host.
// Returns the list of open ports with optional banner.
func ScanPorts(host string, ports []int, timeout time.Duration, concurrency int) []OpenPort {
	return OpenPorts(ScanPortStates(host, ports, timeout, concurrency))
}

// grabBanner sends CRLF and reads the first 256 bytes of the response.
func grabBanner(conn net.Conn, timeout time.Duration) string {
	conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte("\r\n"))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		return string(buf[:n])
	}
	return ""
}
