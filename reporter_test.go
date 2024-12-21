package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortBySeverity(t *testing.T) {
	vulnerabilities := []vulnerabilityInfo{
		{Severity: "High", Vulnerability: "CVE-1234"},
		{Severity: "Medium", Vulnerability: "CVE-5678"},
		{Severity: "Critical", Vulnerability: "CVE-9101"},
	}
	SeverityMap = map[string]int{"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
	sortBySeverity(vulnerabilities)

	// Expect descending order of severity
	assert.Equal(t, "Critical", vulnerabilities[0].Severity)
	assert.Equal(t, "High", vulnerabilities[1].Severity)
	assert.Equal(t, "Medium", vulnerabilities[2].Severity)
}

func TestFilterApproved(t *testing.T) {
	vulnerabilities := []vulnerabilityInfo{
		{Vulnerability: "CVE-1234"},
		{Vulnerability: "CVE-5678"},
	}
	unapproved := []string{"CVE-1234"}

	filtered := filterApproved(vulnerabilities, unapproved, false)

	assert.Len(t, filtered, 1)
	assert.Equal(t, "CVE-1234", filtered[0].Vulnerability)
}

func TestPrintTable(t *testing.T) {
	vulnerabilities := []vulnerabilityInfo{
		{Vulnerability: "CVE-1234", Severity: "High", FeatureName: "libx", FeatureVersion: "1.0", Description: "Test", Link: "http://example.com"},
	}
	unapproved := []string{"CVE-1234"}
	buffer := &bytes.Buffer{}

	printTable(buffer, vulnerabilities, unapproved)

	assert.Contains(t, buffer.String(), "CVE-1234")
	assert.Contains(t, buffer.String(), "High")
	assert.Contains(t, buffer.String(), "libx")
}

func TestReportToFile(t *testing.T) {
	vulnerabilities := []vulnerabilityInfo{
		{Vulnerability: "CVE-1234", Severity: "High"},
	}
	unapproved := []string{"CVE-1234"}

	jsonData, err := reportToFile("test-image", vulnerabilities, unapproved, "output.json")
	assert.NoError(t, err)

	// Parse the JSON to validate its structure
	var result map[string]interface{}
	err = json.Unmarshal(jsonData, &result)
	assert.NoError(t, err)

	// Validate specific fields
	assert.Equal(t, "test-image", result["image"])
	assert.Equal(t, []interface{}{"CVE-1234"}, result["unapproved"])
	assert.Len(t, result["vulnerabilities"], 1)

	vuln := result["vulnerabilities"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, "CVE-1234", vuln["vulnerability"])
	assert.Equal(t, "High", vuln["severity"])
}
