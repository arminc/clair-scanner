package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"

	"github.com/coreos/clair/api/v1"
)

func analyzeLayers(layerIds []string, clairURL string, scannerIP string) {
	tmpPath := "http://" + scannerIP + ":" + strconv.Itoa(httpPort)

	for i := 0; i < len(layerIds); i++ {
		log.Printf("Analyzing %s\n", layerIds[i])

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
		log.Fatalf("Could not analyze layer, payload is not json %s", err)
	}

	request, err := http.NewRequest("POST", clairURL+postLayerURI, bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Fatalf("Could not analyze layer, could not prepare request for Clair %s", err)
	}

	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Fatalf("Could not analyze layer, POST to Clair failed %s", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 201 {
		body, _ := ioutil.ReadAll(response.Body)
		log.Fatalf("Could not analyze layer, Clair responded with a failure: Got response %d with message %s", response.StatusCode, string(body))
	}
}
