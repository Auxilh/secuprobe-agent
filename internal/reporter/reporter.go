package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Auxilh/secuprobe-agent/internal/scanner"
)

// Report is the payload sent to the SecuProbe backend.
type Report struct {
	Hostname string        `json:"hostname"`
	Results  ReportResults `json:"results"`
}

// ReportResults contains the scan findings. CVE correlation is done server-side
// from the detected services, so the agent does not send a cves array.
type ReportResults struct {
	OpenPorts []scanner.OpenPort    `json:"openPorts"`
	Services  []scanner.ServiceInfo `json:"services"`
	// PortStates lists every scanned port with its state (open, closed,
	// filtered, unreachable). Older servers ignore it.
	PortStates []scanner.PortState `json:"portStates,omitempty"`
	// Coverage counts the scanned ports by state, so connection failures
	// (filtered, unreachable) are reported instead of silently dropped (F69).
	// Older servers ignore it.
	Coverage *Coverage `json:"coverage,omitempty"`
}

// Coverage summarizes what the scan could actually observe.
type Coverage struct {
	PortList    string `json:"portList"`
	Scanned     int    `json:"scanned"`
	Open        int    `json:"open"`
	Closed      int    `json:"closed"`
	Filtered    int    `json:"filtered"`
	Unreachable int    `json:"unreachable"`
}

// Summarize counts port states.
func Summarize(states []scanner.PortState) *Coverage {
	c := &Coverage{PortList: fmt.Sprintf("common-%d", len(scanner.CommonPorts)), Scanned: len(states)}
	for _, s := range states {
		switch s.State {
		case scanner.StateOpen:
			c.Open++
		case scanner.StateClosed:
			c.Closed++
		case scanner.StateFiltered:
			c.Filtered++
		default:
			c.Unreachable++
		}
	}
	return c
}

// Send posts the report to the SecuProbe backend.
// Returns the scan ID on success.
func Send(reportURL, agentToken string, report Report) (string, error) {
	payload, err := json.Marshal(report)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodPost, reportURL, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+agentToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ScanID string `json:"scanId"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	return result.ScanID, nil
}
