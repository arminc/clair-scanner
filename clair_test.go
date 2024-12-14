package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
)

// TestParseReportID tests the parseReportID function
func TestParseReportID(t *testing.T) {
	data := []byte(`{"manifest_hash": "dummy-report-id"}`)
	reportID, err := parseReportID(data)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if reportID != "dummy-report-id" {
		t.Errorf("Expected report ID to be 'dummy-report-id', got '%s'", reportID)
	}
}

// TestParseVulnerabilityReport tests the parseVulnerabilityReport function
func TestParseVulnerabilityReport(t *testing.T) {
	data := []byte(`{
		"vulnerabilities": {
			"CVE-1234": {
				"name": "CVE-1234",
				"severity": "High",
				"description": "Test vulnerability",
				"package": {"name": "test-package", "version": "1.0"},
				"links": "http://example.com"
			}
		}
	}`)

	vulnerabilities, err := parseVulnerabilityReport(data)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(vulnerabilities) != 1 {
		t.Fatalf("Expected 1 vulnerability, got %d", len(vulnerabilities))
	}
	if vulnerabilities[0].FeatureName != "test-package" {
		t.Errorf("Expected FeatureName to be 'test-package', got '%s'", vulnerabilities[0].FeatureName)
	}
}

// TestFetchVulnerabilities tests the fetchVulnerabilities function
func TestFetchVulnerabilities(t *testing.T) {
	mockClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/matcher/api/v1/vulnerability_report/dummy-report-id" {
				return &http.Response{
					StatusCode: 200,
					Body: io.NopCloser(bytes.NewReader([]byte(`{
						"vulnerabilities": {
							"CVE-1234": {
								"name": "CVE-1234",
								"severity": "High",
								"description": "Test vulnerability",
								"package": {"name": "test-package", "version": "1.0"},
								"links": "http://example.com"
							}
						}
					}`))),
				}, nil
			}
			return nil, errors.New("unexpected request")
		},
	}

	headers := map[string]string{"Authorization": "Bearer dummy-token"}
	clairURL := "http://example.com"
	reportID := "dummy-report-id"

	vulnerabilities, err := fetchVulnerabilities(mockClient, headers, clairURL, reportID)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(vulnerabilities) != 1 {
		t.Fatalf("Expected 1 vulnerability, got %d", len(vulnerabilities))
	}
	if vulnerabilities[0].FeatureName != "test-package" {
		t.Errorf("Expected FeatureName to be 'test-package', got '%s'", vulnerabilities[0].FeatureName)
	}
}
