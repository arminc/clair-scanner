package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/coreos/clair/api/v1"
)

const (
	postLayerURI        = "/v1/layers"
	getLayerFeaturesURI = "/v1/layers/%s?vulnerabilities"
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

// analyzeLayer tells Clair which layers to analyze
func analyzeLayers(layerIds []string, clairURL string, scannerIP string) {
	tmpPath := "http://" + scannerIP + ":" + httpPort

	for i := 0; i < len(layerIds); i++ {
		logger.Infof("Analyzing %s", layerIds[i])

		if i > 0 {
			analyzeLayer(clairURL, tmpPath+"/"+layerIds[i]+"/layer.tar", layerIds[i], layerIds[i-1])
		} else {
			analyzeLayer(clairURL, tmpPath+"/"+layerIds[i]+"/layer.tar", layerIds[i], "")
		}
	}
}

// analyzeLayer pushes the required information to Clair to scan the layer
func analyzeLayer(clairURL, path, layerName, parentLayerName string) {
	payload := v1.LayerEnvelope{
		Layer: &v1.Layer{
			Name:       layerName,
			Path:       path,
			ParentName: parentLayerName,
			Format:     "Docker",
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		logger.Fatalf("Could not analyze layer: payload is not JSON %v", err)
	}

	request, err := http.NewRequest("POST", clairURL+postLayerURI, bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.Fatalf("Could not analyze layer: could not prepare request for Clair %v", err)
	}

	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		logger.Fatalf("Could not analyze layer: POST to Clair failed %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 201 {
		body, _ := ioutil.ReadAll(response.Body)
		logger.Fatalf("Could not analyze layer: Clair responded with a failure: Got response %d with message %s", response.StatusCode, string(body))
	}
}

// getVulnerabilities fetches vulnerabilities from Clair and extracts the required information
func getVulnerabilities(config scannerConfig, layerIds []string) []vulnerabilityInfo {
	var vulnerabilities = make([]vulnerabilityInfo, 0)
	//Last layer gives you all the vulnerabilities of all layers
	rawVulnerabilities := fetchLayerVulnerabilities(config.clairURL, layerIds[len(layerIds)-1])
	if len(rawVulnerabilities.Features) == 0 {
		if config.exitWhenNoFeatures {
			logger.Fatal("Could not fetch vulnerabilities. No features have been detected in the image. This usually means that the image isn't supported by Clair")
		}
		return nil
	}

	for _, feature := range rawVulnerabilities.Features {
		if len(feature.Vulnerabilities) > 0 {
			for _, vulnerability := range feature.Vulnerabilities {
				vulnerability := vulnerabilityInfo{feature.Name, feature.Version, vulnerability.Name, vulnerability.NamespaceName, vulnerability.Description, vulnerability.Link, vulnerability.Severity, vulnerability.FixedBy}
				vulnerabilities = append(vulnerabilities, vulnerability)
			}
		}
	}
	return vulnerabilities
}

// fetchLayerVulnerabilities fetches vulnerabilities from Clair
func fetchLayerVulnerabilities(clairURL string, layerID string) v1.Layer {
	response, err := http.Get(clairURL + fmt.Sprintf(getLayerFeaturesURI, layerID))
	if err != nil {
		logger.Fatalf("Fetch vulnerabilities, Clair responded with a failure %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		body, _ := ioutil.ReadAll(response.Body)
		logger.Fatalf("Fetch vulnerabilities, Clair responded with a failure: Got response %d with message %s", response.StatusCode, string(body))
	}

	var apiResponse v1.LayerEnvelope
	if err = json.NewDecoder(response.Body).Decode(&apiResponse); err != nil {
		logger.Fatalf("Fetch vulnerabilities, Could not decode response %v", err)
	} else if apiResponse.Error != nil {
		logger.Fatalf("Fetch vulnerabilities, Response contains errors %s", apiResponse.Error.Message)
	}

	return *apiResponse.Layer
}
