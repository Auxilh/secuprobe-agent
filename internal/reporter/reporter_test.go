package reporter

import (
	"testing"

	"github.com/Auxilh/secuprobe-agent/internal/scanner"
)

func TestSummarizeCountsConnectionFailures(t *testing.T) {
	c := Summarize([]scanner.PortState{
		{Port: 22, State: scanner.StateOpen},
		{Port: 23, State: scanner.StateClosed},
		{Port: 25, State: scanner.StateFiltered},
		{Port: 80, State: scanner.StateUnreachable},
	})
	if c.Scanned != 4 || c.Open != 1 || c.Closed != 1 || c.Filtered != 1 || c.Unreachable != 1 {
		t.Fatalf("got %+v", c)
	}
	if c.PortList == "" {
		t.Fatal("port list label missing")
	}
}
