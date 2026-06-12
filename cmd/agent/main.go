package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Auxilh/secuprobe-agent/internal/reporter"
	"github.com/Auxilh/secuprobe-agent/internal/scanner"
)

// Version is injected at build time via ldflags.
var Version = "dev"

func main() {
	agentToken := getEnv("AGENT_TOKEN", "")
	reportURL := getEnv("REPORT_URL", "https://secuprobe.io/api/agent/report")
	targetHost := getEnv("SCAN_TARGET", "127.0.0.1")
	timeout := 2 * time.Second

	if agentToken == "" {
		fmt.Fprintln(os.Stderr, "Error: AGENT_TOKEN environment variable is required")
		os.Exit(1)
	}

	fmt.Printf("SecuProbe Agent %s\n", Version)
	fmt.Printf("Scanning host: %s\n", targetHost)
	fmt.Printf("Report URL: %s\n", reportURL)
	fmt.Println("---")

	// Port scan
	fmt.Printf("Scanning %d ports...\n", len(scanner.TOP_1000_PORTS))
	openPorts := scanner.ScanPorts(targetHost, scanner.TOP_1000_PORTS, timeout, 100)
	fmt.Printf("Found %d open port(s)\n", len(openPorts))

	// CVE lookup for detected services
	var cves []scanner.CVEMatch
	serviceKeywords := extractServiceKeywords(openPorts)
	for _, kw := range serviceKeywords {
		fmt.Printf("Looking up CVEs for: %s\n", kw)
		matches, err := scanner.LookupCVEsForService(kw, 5)
		if err != nil {
			fmt.Fprintf(os.Stderr, "CVE lookup error for %s: %v\n", kw, err)
			continue
		}
		cves = append(cves, matches...)
	}
	fmt.Printf("Found %d CVE(s)\n", len(cves))

	// Build hostname
	hostname := targetHost

	// Send report
	fmt.Println("Sending report to SecuProbe...")
	report := reporter.Report{
		Hostname: hostname,
		Results: reporter.ReportResults{
			OpenPorts: openPorts,
			CVEs:      cves,
		},
	}

	scanID, err := reporter.Send(reportURL, agentToken, report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Report submitted successfully. Scan ID: %s\n", scanID)
}

// extractServiceKeywords maps well-known ports to service keywords for CVE lookup.
func extractServiceKeywords(ports []scanner.OpenPort) []string {
	portToService := map[int]string{
		21:    "OpenSSH FTP",
		22:    "OpenSSH",
		80:    "Apache nginx",
		443:   "OpenSSL",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
		8080:  "Apache Tomcat",
		9200:  "Elasticsearch",
	}

	seen := map[string]bool{}
	var keywords []string
	for _, p := range ports {
		if kw, ok := portToService[p.Port]; ok {
			for _, k := range strings.Fields(kw) {
				if !seen[k] {
					seen[k] = true
					keywords = append(keywords, k)
				}
			}
		}
	}
	return keywords
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
