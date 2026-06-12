package scanner

import (
	"fmt"
	"net"
	"sort"
	"sync"
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

// ScanPorts performs a concurrent TCP port scan on the given host.
// Returns the list of open ports with optional banner.
func ScanPorts(host string, ports []int, timeout time.Duration, concurrency int) []OpenPort {
	if concurrency <= 0 {
		concurrency = 100
	}

	type result struct {
		port   int
		open   bool
		banner string
	}

	jobs := make(chan int, len(ports))
	results := make(chan result, len(ports))

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				address := fmt.Sprintf("%s:%d", host, port)
				conn, err := net.DialTimeout("tcp", address, timeout)
				if err != nil {
					results <- result{port: port, open: false}
					continue
				}
				// Grab banner
				banner := grabBanner(conn, timeout)
				conn.Close()
				results <- result{port: port, open: true, banner: banner}
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

	var open []OpenPort
	for r := range results {
		if r.open {
			open = append(open, OpenPort{
				Port:     r.port,
				Protocol: "tcp",
				Banner:   r.banner,
			})
		}
	}

	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
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
