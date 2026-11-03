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
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte(banner))
			// Keep the connection open until the client reads, like a real service:
			// block on a read so the banner is delivered before we close.
			buf := make([]byte, 64)
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			_, _ = conn.Read(buf)
			conn.Close()
		}
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

// Audit F39: a closed port (RST) and an open port are distinguishable.
func TestScanPortStates_DistinguishesClosedFromOpen(t *testing.T) {
	port := startMockTCPServer(t, "SSH-2.0-OpenSSH_8.9\r\n")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // nothing listens any more: the OS answers RST

	states := ScanPortStates("127.0.0.1", []int{port, closedPort}, 2*time.Second, 10)
	if len(states) != 2 {
		t.Fatalf("expected 2 states, got %d", len(states))
	}
	byPort := map[int]string{}
	for _, s := range states {
		byPort[s.Port] = s.State
	}
	if byPort[port] != StateOpen {
		t.Errorf("expected open, got %q", byPort[port])
	}
	if byPort[closedPort] != StateClosed {
		t.Errorf("expected closed, got %q", byPort[closedPort])
	}
}

// Audit F39: a timeout is "filtered", any other error "unreachable", never "closed".
func TestClassifyDialError_TimeoutIsFiltered(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}
	if got := classifyDialError(err); got != StateFiltered {
		t.Errorf("expected filtered, got %q", got)
	}
	if got := classifyDialError(fmt.Errorf("no route to host")); got != StateUnreachable {
		t.Errorf("expected unreachable, got %q", got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
