package targets

import "testing"

func TestParseSingleIP(t *testing.T) {
	hosts, err := Parse("10.0.0.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "10.0.0.5" {
		t.Fatalf("got %v", hosts)
	}
}

func TestParseList(t *testing.T) {
	hosts, err := Parse("10.0.0.1, 10.0.0.2 srv.local;10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Duplicate 10.0.0.1 is removed; order preserved.
	want := []string{"10.0.0.1", "10.0.0.2", "srv.local"}
	if len(hosts) != len(want) {
		t.Fatalf("got %v", hosts)
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Fatalf("got %v want %v", hosts, want)
		}
	}
}

func TestParseCIDRSkipsNetworkAndBroadcast(t *testing.T) {
	hosts, err := Parse("192.168.1.0/29")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /29 = 8 addresses, minus network (.0) and broadcast (.7) = 6 usable.
	if len(hosts) != 6 || hosts[0] != "192.168.1.1" || hosts[5] != "192.168.1.6" {
		t.Fatalf("got %v", hosts)
	}
}

func TestParseRejectsTooLargeRange(t *testing.T) {
	if _, err := Parse("10.0.0.0/8"); err == nil {
		t.Fatal("expected error for oversized range")
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	if _, err := Parse("   "); err == nil {
		t.Fatal("expected error for empty spec")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse("not a host!!"); err == nil {
		t.Fatal("expected error for invalid target")
	}
}
