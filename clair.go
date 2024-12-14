package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/arminc/clair-scanner/pkg/types"
	"github.com/quay/claircore"
)

const (
	indexerURI = "/indexer/api/v1/index_report"
	reportURI  = "/indexer/api/v1/index_report/%s"
	matcherURI = "/matcher/api/v1/vulnerability_report/%s"
)

type vulnerabilityInfo struct {
	FeatureName    string `json:"featurename"`
	FeatureVersion string `json:"featureversion"`
	Vulnerability  string `json:"vulnerability"`
	Namespace      string `json:"namespace"`
	Description    string `json:"description"`
	Link           string `json:"link"`
	Severity       string `json:"severity"`
	FixedBy        string `json:"fixedby"`
}

type VulnerabilityReport struct {
	Vulnerabilities map[string]claircore.Vulnerability `json:"vulnerabilities"`
}

func analyzeContainer(client HTTPClient, headers map[string]string, clairURL string, payloadJSON types.Payload) (string, error) {
	payloadBytes, err := json.Marshal(payloadJSON)
	if err != nil {
		return "", fmt.Errorf("error marshaling payload: %w", err)
	}

	req, err := http.NewRequest("POST", clairURL+indexerURI, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %w", err)
	}

	reportID, err := parseReportID(body)
	if err != nil {
		return "", fmt.Errorf("error parsing report ID: %w", err)
	}

	return reportID, nil
}

func waitForSuccessfulResponse(client HTTPClient, headers map[string]string, clairURL, reportID string) (*http.Response, error) {
	for attempt := 0; attempt < 30; attempt++ {
		time.Sleep(1 * time.Second)

		resp, err := getRequest(client, clairURL+fmt.Sprintf(reportURI, reportID), headers)
		if err != nil {
			log.Printf("Error during HTTP request: %v", err)
			continue
		}

		if resp.StatusCode == 200 {
			return resp, nil
		} else if resp.StatusCode == 404 {
			log.Println("Index report not yet complete, retrying...")
		} else {
			return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}
	}
	return nil, fmt.Errorf("index report did not complete in expected time")
}

func fetchVulnerabilities(client HTTPClient, headers map[string]string, clairURL, reportID string) ([]vulnerabilityInfo, error) {
	resp, err := getRequest(client, clairURL+fmt.Sprintf(matcherURI, reportID), headers)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	vulnerabilities, err := parseVulnerabilityReport(bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("error decoding vulnerability report: %w", err)
	}

	return vulnerabilities, nil
}

// Helper to parse JSON for report ID
func parseReportID(data []byte) (string, error) {
	var response map[string]interface{}
	if err := json.Unmarshal(data, &response); err != nil {
		return "", fmt.Errorf("error unmarshaling report ID: %w", err)
	}

	reportID, ok := response["manifest_hash"].(string)
	if !ok {
		return "", fmt.Errorf("manifest_hash not found in response")
	}

	return reportID, nil
}

// Helper to parse vulnerability report
func parseVulnerabilityReport(data []byte) ([]vulnerabilityInfo, error) {
	var report VulnerabilityReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("error unmarshaling vulnerability report: %w", err)
	}

	var vulnerabilities []vulnerabilityInfo
	for _, vuln := range report.Vulnerabilities {
		// Safely handle fields that may be nil
		var featureName, featureVersion, namespace, description, link, severity, fixedBy string

		if vuln.Package != nil {
			featureName = vuln.Package.Name
			featureVersion = vuln.Package.Version
		}
		if vuln.Dist != nil {
			namespace = vuln.Dist.DID
		}
		description = vuln.Description
		link = vuln.Links
		severity = vuln.NormalizedSeverity.String()
		fixedBy = vuln.FixedInVersion

		// Append to vulnerabilities list
		vulnerabilities = append(vulnerabilities, vulnerabilityInfo{
			FeatureName:    featureName,
			FeatureVersion: featureVersion,
			Vulnerability:  vuln.Name,
			Namespace:      namespace,
			Description:    description,
			Link:           link,
			Severity:       severity,
			FixedBy:        fixedBy,
		})
	}

	return vulnerabilities, nil
}

func getRequest(client HTTPClient, url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating GET request: %w", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error executing GET request: %w", err)
	}

	return resp, nil
}
