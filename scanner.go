package main

import (
	"context"
	"os"
	"strings"
)

type vulnerabilitiesWhitelist struct {
	GeneralWhitelist map[string]string            //[key: CVE and value: CVE description]
	Images           map[string]map[string]string // image name with [key: CVE and value: CVE description]
}

const tmpPrefix = "clair-scanner-"

type scannerConfig struct {
	imageName          string
	whitelist          vulnerabilitiesWhitelist
	clairURL           string
	scannerIP          string
	reportFile         string
	whitelistThreshold string
	reportAll          bool
	quiet              bool
	exitWhenNoFeatures bool
}

// scan orchestrates the scanning process of an image
func scan(config scannerConfig) []string {
	//Create a temporary folder where the docker image layers are going to be stored
	tmpPath := createTmpPath(tmpPrefix)
	defer os.RemoveAll(tmpPath)

	saveDockerImage(config.imageName, tmpPath)
	layerIds := getImageLayerIds(tmpPath)

	//Start a server that can serve Docker image layers to Clair
	server := httpFileServer(tmpPath)
	defer server.Shutdown(context.TODO())

	//Analyze the layers
	analyzeLayers(layerIds, config.clairURL, config.scannerIP)
	vulnerabilities := getVulnerabilities(config, layerIds)

	if vulnerabilities == nil {
		return nil // exit when no features
	}

	//Check vulnerabilities against whitelist and report
	unapproved := checkForUnapprovedVulnerabilities(config.imageName, vulnerabilities, config.whitelist, config.whitelistThreshold)

	// Report vulnerabilities
	reportToConsole(config.imageName, vulnerabilities, unapproved, config.reportAll, config.quiet)
	reportToFile(config.imageName, vulnerabilities, unapproved, config.reportFile)

	return unapproved
}

// checkForUnapprovedVulnerabilities checks if the found vulnerabilities are approved or not in the whitelist
func checkForUnapprovedVulnerabilities(imageName string, vulnerabilities []vulnerabilityInfo, whitelist vulnerabilitiesWhitelist, whitelistThreshold string) []string {
	unapproved := []string{}
	imageVulnerabilities := getImageVulnerabilities(imageName, whitelist.Images)

	for i := 0; i < len(vulnerabilities); i++ {
		vulnerability := vulnerabilities[i].Vulnerability
		severity := vulnerabilities[i].Severity
		vulnerable := true

		//Check if the vulnerability has a severity less than our threshold severity
		if SeverityMap[severity] > SeverityMap[whitelistThreshold] {
			vulnerable = false
		}

		//Check if the vulnerability exists in the GeneralWhitelist
		if vulnerable {
			if _, exists := whitelist.GeneralWhitelist[vulnerability]; exists {
				vulnerable = false
			}
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
