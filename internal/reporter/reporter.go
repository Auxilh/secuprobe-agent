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
	Hostname string          `json:"hostname"`
	Results  ReportResults   `json:"results"`
}

// ReportResults contains the scan findings. CVE correlation is done server-side
// from the detected services, so the agent does not send a cves array.
type ReportResults struct {
	OpenPorts []scanner.OpenPort   `json:"openPorts"`
	Services  []scanner.ServiceInfo `json:"services"`
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
