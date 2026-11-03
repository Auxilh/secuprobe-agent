package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Auxilh/secuprobe-agent/internal/reporter"
	"github.com/Auxilh/secuprobe-agent/internal/scanner"
	"github.com/Auxilh/secuprobe-agent/internal/targets"
)

// Version is injected at build time via ldflags.
var Version = "dev"

func main() {
	agentToken := getEnv("AGENT_TOKEN", "")
	reportURL := getEnv("REPORT_URL", "https://secuprobe.io/api/agent/report")
	targetSpec := firstNonEmpty(os.Getenv("SCAN_TARGETS"), os.Getenv("SCAN_TARGET"))
	timeout := envDuration("SCAN_TIMEOUT_MS", 2*time.Second)
	concurrency := envInt("SCAN_CONCURRENCY", 100)
	// Run as a daemon by default: scan every hour. SCAN_INTERVAL_SECONDS=0 runs once and exits.
	interval := time.Duration(envIntAllowZero("SCAN_INTERVAL_SECONDS", 3600)) * time.Second

	if agentToken == "" {
		fmt.Fprintln(os.Stderr, "Error: AGENT_TOKEN environment variable is required")
		os.Exit(1)
	}
	if !strings.HasPrefix(agentToken, "spagent_") {
		fmt.Fprintln(os.Stderr, "Error: AGENT_TOKEN is malformed (expected an spagent_ token)")
		os.Exit(1)
	}

	// No target configured → scan this host as seen from the network.
	if strings.TrimSpace(targetSpec) == "" {
		targetSpec = targets.LocalDefault()
	}

	hosts, err := targets.Parse(targetSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("SecuProbe Agent %s\n", Version)
	fmt.Printf("Report URL: %s\n", reportURL)
	fmt.Printf("Targets: %d host(s)\n", len(hosts))
	if interval > 0 {
		fmt.Printf("Interval: every %s\n", interval)
	} else {
		fmt.Println("Interval: single run")
	}
	fmt.Println("---")

	for {
		failures := scanCycle(reportURL, agentToken, hosts, timeout, concurrency)
		if interval <= 0 {
			if failures > 0 {
				os.Exit(1)
			}
			return
		}
		fmt.Printf("Next scan in %s\n", interval)
		time.Sleep(interval)
	}
}

// scanCycle scans every host once and reports each, returning the number of
// failed reports. Every reachable host is reported, even with no open port, so
// the dashboard shows it was scanned.
func scanCycle(reportURL, token string, hosts []string, timeout time.Duration, concurrency int) int {
	var failures int
	for i, host := range hosts {
		fmt.Printf("[%d/%d] Scanning %s (%d ports)...\n", i+1, len(hosts), host, len(scanner.TOP_1000_PORTS))
		states := scanner.ScanPortStates(host, scanner.TOP_1000_PORTS, timeout, concurrency)
		openPorts := scanner.OpenPorts(states)
		fmt.Printf("        %d open port(s)\n", len(openPorts))

		if err := send(reportURL, token, host, openPorts, states); err != nil {
			fmt.Fprintf(os.Stderr, "        report error: %v\n", err)
			failures++
			continue
		}
		fmt.Printf("        reported\n")
	}
	fmt.Println("---")
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "Cycle done with %d/%d host report(s) failing\n", failures, len(hosts))
	} else {
		fmt.Printf("Cycle done. %d host(s) reported.\n", len(hosts))
	}
	return failures
}

// send builds and posts the report for a single host. CVE correlation from the
// detected services is done server-side (the backend owns the NVD key and cache),
// so the agent stays small and needs no outbound internet beyond the report URL.
func send(reportURL, token, host string, openPorts []scanner.OpenPort, states []scanner.PortState) error {
	report := reporter.Report{
		Hostname: host,
		Results: reporter.ReportResults{
			OpenPorts:  openPorts,
			Services:   scanner.IdentifyServices(openPorts),
			PortStates: states,
		},
	}
	_, err := reporter.Send(reportURL, token, report)
	return err
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// envIntAllowZero parses a non-negative integer, honoring an explicit 0.
func envIntAllowZero(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Millisecond
		}
	}
	return def
}
