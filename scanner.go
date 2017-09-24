package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
)

type vulnerabilitiesWhitelist struct {
	GeneralWhitelist map[string]string            //[key: CVE and value: CVE description]
	Images           map[string]map[string]string // image name with [key: CVE and value: CVE description]
}

type vulnerabilityReport struct {
	Image           string              `json:"image"`
	Unaproved       []string            `json:"unaproved"`
	Vulnerabilities []vulnerabilityInfo `json:"vulnerabilities"`
}

const tmpPrefix = "clair-scanner-"

type scannerConfig struct {
	imageName  string
	whitelist  vulnerabilitiesWhitelist
	clairURL   string
	scannerIP  string
	reportFile string
}

// scan orchestrates the scanning process of an image
func scan(config scannerConfig) {
	//Create a temporary folder where the docker image layers are going to be stored
	tmpPath := createTmpPath(tmpPrefix)
	defer os.RemoveAll(tmpPath)

	saveDockerImage(config.imageName, tmpPath)
	layerIds := getImageLayerIds(tmpPath)

	//Start a server that can serve Docker image layers to Clair
	server := httpFileServer(tmpPath)
	defer server.Shutdown(nil)

	//Analyze the layers
	analyzeLayers(layerIds, config.clairURL, config.scannerIP)
	vulnerabilities := getVulnerabilities(config.clairURL, layerIds)

	//Check vulnerabilities against whitelist and report
	unapproved := checkForUnapprovedVulnerabilities(config.imageName, vulnerabilities, config.whitelist)
	printReport(config.imageName, vulnerabilities, unapproved, config.reportFile)
}

// checkForUnapprovedVulnerabilities checks if the found vulnerabilities are approved or not in the whitelist
func checkForUnapprovedVulnerabilities(imageName string, vulnerabilities []vulnerabilityInfo, whitelist vulnerabilitiesWhitelist) []string {
	unapproved := []string{}
	imageVulnerabilities := getImageVulnerabilities(imageName, whitelist.Images)

	for i := 0; i < len(vulnerabilities); i++ {
		vulnerability := vulnerabilities[i].Vulnerability
		vulnerable := true

		//Check if the vulnerability exists in the GeneralWhitelist
		if _, exists := whitelist.GeneralWhitelist[vulnerability]; exists {
			vulnerable = false
		}

		//If not in GeneralWhitelist check if the vulnerability exists in the imageVulnerabilities
		if vulnerable && len(imageVulnerabilities) > 0 {
			if _, exists := imageVulnerabilities[vulnerability]; exists {
				vulnerable = false
			}
		}
		if vulnerable {
			unapproved = append(unapproved, vulnerability)
		}
	}
	return unapproved
}

// getImageVulnerabilities returns image specific whitelist of vulnerabilities from whitelistImageVulnerabilities
func getImageVulnerabilities(imageName string, whitelistImageVulnerabilities map[string]map[string]string) map[string]string {
	var imageVulnerabilities map[string]string
	imageWithoutVersion := strings.Split(imageName, ":") // TODO there is a bug here if it is a private registry with a custom port registry:777/ubuntu:tag
	if val, exists := whitelistImageVulnerabilities[imageWithoutVersion[0]]; exists {
		imageVulnerabilities = val
	}
	return imageVulnerabilities
}

// printReport shows the unapproved vulnerabilities and writes a report to file
func printReport(imageName string, vulnerabilities []vulnerabilityInfo, unapproved []string, file string) {
	if len(unapproved) > 0 {
		logger.Infof("Unapproved vulnerabilities [%s]", unapproved)
	} else {
		logger.Infof("Image [%s] not vulnerable", imageName)
	}

	if file != "" {
		report := &vulnerabilityReport{
			Image:           imageName,
			Vulnerabilities: vulnerabilities,
			Unaproved:       unapproved,
		}
		reportToFile(report, file)
	}
}

// reportToFile writes the report to file
func reportToFile(report *vulnerabilityReport, file string) {
	reportJSON, err := json.MarshalIndent(report, "", "    ")
	if err != nil {
		logger.Fatalf("Could not create a report: report is not proper JSON %v", err)
	}
	if err = ioutil.WriteFile(file, reportJSON, 0644); err != nil {
		logger.Fatalf("Could not create a report: could not write to file %v", err)
	}
}
