package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
)

type vulnerabilityInfo struct {
	Vulnerability string `json:"vulnerability"`
	Namespace     string `json:"namespace"`
	Severity      string `json:"severity"`
}

type acceptedVulnerability struct {
	Cve         string
	Description string
}

type vulnerabilitiesWhitelist struct {
	GeneralWhitelist map[string]string
	Images           map[string]map[string]string
}

type vulnerabilityReport struct {
	Image           string              `json:"image"`
	Unaproved       []string            `json:"unaproved"`
	Vulnerabilities []vulnerabilityInfo `json:"vulnerabilities"`
}

func scan(imageName string, whitelist vulnerabilitiesWhitelist, clairURL string, scannerIP string, reportFile string) {
	//Create a temporary folder where the docker image layers are going to be stored
	tmpPath := createTmpPath(tmpPrefix)
	defer os.RemoveAll(tmpPath)

	saveDockerImage(imageName, tmpPath)
	layerIds := getImageLayerIds(tmpPath)

	//Start a server that can serve Docker image layers to Clair
	server := httpFileServer(tmpPath)
	defer server.Shutdown(nil)

	analyzeLayers(layerIds, clairURL, scannerIP)
	vulnerabilities := getVulnerabilities(clairURL, layerIds)

	unapproved := vulnerabilitiesApproved(imageName, vulnerabilities, whitelist)
	printReport(imageName, vulnerabilities, unapproved, reportFile)
}

func printReport(imageName string, vulnerabilities []vulnerabilityInfo, unapproved []string, file string) {
	if len(unapproved) > 0 {
		Logger.Infof("Unaproved vulnerabilities [%s]", unapproved)
	} else {
		Logger.Infof("Image [%s] not vulnerable", imageName)
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

func reportToFile(report *vulnerabilityReport, file string) {
	reportJSON, err := json.MarshalIndent(report, "", "    ")
	if err != nil {
		Logger.Fatalf("Could not create a report, report not proper json %v", err)
	}
	if err = ioutil.WriteFile(file, reportJSON, 0644); err != nil {
		Logger.Fatalf("Could not create a report, could not write to file %v", err)
	}
}

func getVulnerabilities(clairURL string, layerIds []string) []vulnerabilityInfo {
	var vulnerabilities = make([]vulnerabilityInfo, 0)
	//Last layer gives you all the vulnerabilities of all layers
	rawVulnerabilities := fetchLayerVulnerabilities(clairURL, layerIds[len(layerIds)-1])
	if len(rawVulnerabilities.Features) == 0 {
		Logger.Fatal("Could not fetch vulnerabilities. No features have been detected in the image. This usually means that the image isn't supported by Clair")
	}

	for _, feature := range rawVulnerabilities.Features {
		if len(feature.Vulnerabilities) > 0 {
			for _, vulnerability := range feature.Vulnerabilities {
				vulnerability := vulnerabilityInfo{vulnerability.Name, vulnerability.NamespaceName, vulnerability.Severity}
				vulnerabilities = append(vulnerabilities, vulnerability)
			}
		}
	}
	return vulnerabilities
}

func vulnerabilitiesApproved(imageName string, vulnerabilities []vulnerabilityInfo, whitelist vulnerabilitiesWhitelist) []string {
	unapproved := []string{}
	imageVulnerabilities := getImageVulnerabilities(imageName, whitelist.Images)

	for i := 0; i < len(vulnerabilities); i++ {
		vulnerability := vulnerabilities[i].Vulnerability
		vulnerable := true

		if _, exists := whitelist.GeneralWhitelist[vulnerability]; exists {
			vulnerable = false
		}
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

func getImageVulnerabilities(imageName string, whitelistImageVulnerabilities map[string]map[string]string) map[string]string {
	var imageVulnerabilities map[string]string
	imageWithoutVersion := strings.Split(imageName, ":")
	if val, exists := whitelistImageVulnerabilities[imageWithoutVersion[0]]; exists {
		imageVulnerabilities = val
	}
	return imageVulnerabilities
}
