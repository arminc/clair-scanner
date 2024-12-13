package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
)

type vulnerabilitiesWhitelist struct {
	GeneralWhitelist map[string]string            //[key: CVE and value: CVE description]
	Images           map[string]map[string]string // image name with [key: CVE and value: CVE description]
}

const tmpPrefix = "clair-scanner-"

type ScannerConfig struct {
	ImageName          string
	Whitelist          vulnerabilitiesWhitelist
	ClairURL           string
	ScannerIP          string
	ReportFile         string
	WhitelistThreshold string
	ReportAll          bool
	Quiet              bool
	ExitWhenNoFeatures bool
}

// HTTPClient defines an interface for making HTTP requests
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Scanner interface {
	Scan(config ScannerConfig) []string
}

type DefaultScanner struct {
	DockerClient DockerClient
	FileSystem   FileSystem
	HTTPClient   HTTPClient
}

func NewDefaultScanner(dockerClient DockerClient, fileSystem FileSystem, httpClient HTTPClient) *DefaultScanner {
	return &DefaultScanner{
		DockerClient: dockerClient,
		FileSystem:   fileSystem,
		HTTPClient:   httpClient,
	}
}

func (ds *DefaultScanner) Scan(config ScannerConfig) []string {
	tmpPath := createTmpPath(tmpPrefix)
	defer os.RemoveAll(tmpPath)

	err := saveDockerImage(ds.DockerClient, config.ImageName, tmpPath)
	if err != nil {
		log.Fatalf("Error saving Docker image: %v", err)
	}

	payloadJSON, err := LoadDockerManifest(tmpPath, config.ScannerIP, ds.FileSystem)
	if err != nil {
		log.Fatalf("Failed to load docker manifest: %s", err)
	}

	server := httpFileServer(tmpPath)
	defer server.Shutdown(context.TODO())

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	reportID, err := analyzeContainer(ds.HTTPClient, headers, config.ClairURL, *payloadJSON)
	if err != nil {
		log.Fatalf("Failed to submit container for analysis: %s", err)
	}

	successfulResponse := waitForSuccessfulResponse(ds.HTTPClient, headers, config.ClairURL, reportID)
	if successfulResponse == nil {
		return nil
	}

	vulnerabilities := fetchVulnerabilities(ds.HTTPClient, headers, config.ClairURL, reportID)
	if vulnerabilities == nil {
		return nil
	}

	unapproved := checkForUnapprovedVulnerabilities(config.ImageName, vulnerabilities, config.Whitelist, config.WhitelistThreshold)
	reportToConsole(config.ImageName, vulnerabilities, unapproved, config.ReportAll, config.Quiet)
	reportToFile(config.ImageName, vulnerabilities, unapproved, config.ReportFile)

	return unapproved
}

func checkForUnapprovedVulnerabilities(imageName string, vulnerabilities []vulnerabilityInfo, whitelist vulnerabilitiesWhitelist, whitelistThreshold string) []string {
	unapproved := []string{}
	imageVulnerabilities := getImageVulnerabilities(imageName, whitelist.Images)

	for _, vuln := range vulnerabilities {
		vulnerable := true
		if SeverityMap[vuln.Severity] > SeverityMap[whitelistThreshold] {
			vulnerable = false
		}
		if _, exists := whitelist.GeneralWhitelist[vuln.Vulnerability]; exists {
			vulnerable = false
		}
		if _, exists := imageVulnerabilities[vuln.Vulnerability]; exists {
			vulnerable = false
		}
		if vulnerable {
			unapproved = append(unapproved, vuln.Vulnerability)
		}
	}
	return unapproved
}

func getImageVulnerabilities(imageName string, whitelistImageVulnerabilities map[string]map[string]string) map[string]string {
	imageWithoutVersion := strings.Split(imageName, ":")[0]
	if val, exists := whitelistImageVulnerabilities[imageWithoutVersion]; exists {
		return val
	}
	return nil
}
