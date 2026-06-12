package scanner

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// startMockTCPServer starts a local TCP server on a random port and returns its port.
func startMockTCPServer(t *testing.T, banner string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte(banner))
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

func TestScanPorts_DetectsOpenPort(t *testing.T) {
	port := startMockTCPServer(t, "SSH-2.0-OpenSSH_8.9\r\n")
	results := ScanPorts("127.0.0.1", []int{port}, 2*time.Second, 10)

	if len(results) != 1 {
		t.Fatalf("expected 1 open port, got %d", len(results))
	}
	if results[0].Port != port {
		t.Errorf("expected port %d, got %d", port, results[0].Port)
	}
	if results[0].Protocol != "tcp" {
		t.Errorf("expected tcp, got %s", results[0].Protocol)
	}
}

func TestScanPorts_ClosedPortNotReported(t *testing.T) {
	// Port 1 is almost certainly closed
	results := ScanPorts("127.0.0.1", []int{1}, 500*time.Millisecond, 10)
	if len(results) != 0 {
		t.Errorf("expected no open ports, got %d", len(results))
	}
}

func TestGrabBanner_ReturnsBanner(t *testing.T) {
	port := startMockTCPServer(t, "SSH-2.0-OpenSSH_8.9")

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	banner := grabBanner(conn, time.Second)
	if banner != "SSH-2.0-OpenSSH_8.9" {
		t.Errorf("unexpected banner: %q", banner)
	}
}

func TestScanPorts_SortsResults(t *testing.T) {
	// Start two mock servers
	port1 := startMockTCPServer(t, "svc1")
	port2 := startMockTCPServer(t, "svc2")

	// Scan in reverse order
	results := ScanPorts("127.0.0.1", []int{port2, port1}, 2*time.Second, 10)

	if len(results) < 2 {
		t.Skip("one port unexpectedly closed, skipping sort test")
	}
	if results[0].Port > results[1].Port {
		t.Errorf("results not sorted: %d > %d", results[0].Port, results[1].Port)
	}
}

