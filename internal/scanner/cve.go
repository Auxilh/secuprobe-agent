package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CVEMatch represents a matched CVE for a detected service.
type CVEMatch struct {
	ID              string `json:"id"`
	Severity        string `json:"severity"`
	Description     string `json:"description"`
	AffectedService string `json:"affectedService,omitempty"`
}

// nvdResponse mirrors the NVD API v2 response structure.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseSeverity string `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV2 []struct {
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// LookupCVEsForService queries NVD API for CVEs matching the given keyword.
func LookupCVEsForService(keyword string, maxResults int) ([]CVEMatch, error) {
	if keyword == "" {
		return nil, nil
	}

	url := fmt.Sprintf(
		"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=%d",
		keyword, maxResults,
	)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return nil, err
	}

	var nvd nvdResponse
	if err := json.Unmarshal(body, &nvd); err != nil {
		return nil, err
	}

	var matches []CVEMatch
	for _, v := range nvd.Vulnerabilities {
		cve := v.CVE
		severity := "unknown"
		if len(cve.Metrics.CVSSMetricV31) > 0 {
			severity = strings.ToLower(cve.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity)
		} else if len(cve.Metrics.CVSSMetricV2) > 0 {
			severity = strings.ToLower(cve.Metrics.CVSSMetricV2[0].BaseSeverity)
		}

		desc := ""
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}

		matches = append(matches, CVEMatch{
			ID:              cve.ID,
			Severity:        severity,
			Description:     desc,
			AffectedService: keyword,
		})
	}
	return matches, nil
}
