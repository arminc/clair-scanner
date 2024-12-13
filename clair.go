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
		log.Fatalf("Error marshaling payload: %v", err)
	}

	req, err := http.NewRequest("POST", clairURL+indexerURI, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Create an HTTP client and send the request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request to server: %v", err)
	}
	defer resp.Body.Close()

	// Read and log the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %v", err)
	}

	// Parse JSON response to extract the report_id
	var responseMap map[string]interface{}
	if err := json.Unmarshal(body, &responseMap); err != nil {
		return "", fmt.Errorf("error parsing JSON response: %v", err)
	}

	// Extract the report_id assuming it's called "manifest_hash"
	reportID, ok := responseMap["manifest_hash"].(string)
	if !ok {
		return "", fmt.Errorf("manifest_hash not found in the response")
	}

	return string(reportID), nil
}

func waitForSuccessfulResponse(client HTTPClient, headers map[string]string, clairURL, reportID string) *http.Response {
	maxAttempts := 30
	for attempt := 0; attempt < maxAttempts; attempt++ {
		time.Sleep(1 * time.Second) // Wait for 1 second before each new attempt

		response, err := getRequest(client, clairURL+fmt.Sprintf(reportURI, reportID), headers)
		if err != nil {
			log.Println("Error during HTTP request:", err)
			continue
		}

		if response.StatusCode == 200 {
			return response
		} else if response.StatusCode == 404 {
			log.Println("Index report not yet complete, retrying...")
		} else {
			log.Printf("Failed to retrieve index report. Status code: %d\n", response.StatusCode)
			break
		}
	}
	log.Println("Index report did not complete in the expected time.")
	return nil
}

func getRequest(client HTTPClient, url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return client.Do(req)
}

func fetchVulnerabilities(client HTTPClient, headers map[string]string, clairURL, reportID string) []vulnerabilityInfo {
	var vulnerabilities []vulnerabilityInfo

	// Send the request
	resp, err := getRequest(client, clairURL+fmt.Sprintf(matcherURI, reportID), headers)
	if err != nil {
		log.Printf("Error during HTTP request: %v", err)
		return nil
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return nil
	}

	// Decode the JSON into VulnerabilityReport
	var report VulnerabilityReport
	if err := json.Unmarshal(bodyBytes, &report); err != nil {
		log.Printf("Error decoding vulnerability report: %v", err)
		return nil
	}

	// Process vulnerabilities
	for _, vuln := range report.Vulnerabilities {
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

	// Log if no vulnerabilities are found
	if len(vulnerabilities) == 0 {
		log.Println("No vulnerabilities found.")
	}

	return vulnerabilities
}
