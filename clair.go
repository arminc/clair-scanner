package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/coreos/clair/api/v1"
)

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
		logger.Fatalf("Could not analyze layer, payload is not json %s", err)
	}

	request, err := http.NewRequest("POST", clairURL+postLayerURI, bytes.NewBuffer(jsonPayload))
	if err != nil {
		logger.Fatalf("Could not analyze layer, could not prepare request for Clair %s", err)
	}

	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		logger.Fatalf("Could not analyze layer, POST to Clair failed %s", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 201 {
		body, _ := ioutil.ReadAll(response.Body)
		logger.Fatalf("Could not analyze layer, Clair responded with a failure: Got response %d with message %s", response.StatusCode, string(body))
	}
}

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
