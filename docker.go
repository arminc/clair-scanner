package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/docker/docker/client"
)

// TODO Add support for older version of docker

type manifestJSON struct {
	Layers []string
}

// saveDockerImage saves Docker image to temorary folder
func saveDockerImage(imageName string, tmpPath string) {
	docker := createDockerClient()

	imageReader, err := docker.ImageSave(context.Background(), []string{imageName})
	if err != nil {
		logger.Fatalf("Could not save Docker image [%s]: %v", imageName, err)
	}

	defer imageReader.Close()

	if err = untar(imageReader, tmpPath); err != nil {
		logger.Fatalf("Could not save Docker image: could not untar [%s]: %v", imageName, err)
	}
}

func createDockerClient() client.APIClient {
	docker, err := client.NewEnvClient()
	if err != nil {
		logger.Fatalf("Could not create a Docker client: %v", err)
	}
	return docker
}

// getImageLayerIds reads LayerIDs from the manifest.json file
func getImageLayerIds(path string) []string {
	manifest := readManifestFile(path)

	var layers []string
	for _, layer := range manifest[0].Layers {
		layers = append(layers, strings.TrimSuffix(layer, "/layer.tar"))
	}
	return layers
}

// readManifestFile reads the local manifest.json
func readManifestFile(path string) []manifestJSON {
	manifestFile := path + "/manifest.json"
	mf, err := os.Open(manifestFile)
	if err != nil {
		logger.Fatalf("Could not read Docker image layers: could not open [%s]: %v", manifestFile, err)
	}
	defer mf.Close()

	return parseAndValidateManifestFile(mf)
}

// parseAndValidateManifestFile parses the manifest.json file and validates it
func parseAndValidateManifestFile(manifestFile io.Reader) []manifestJSON {
	var manifest []manifestJSON
	if err := json.NewDecoder(manifestFile).Decode(&manifest); err != nil {
		logger.Fatalf("Could not read Docker image layers: manifest.json is not json: %v", err)
	} else if len(manifest) != 1 {
		logger.Fatalf("Could not read Docker image layers: manifest.json is not valid")
	} else if len(manifest[0].Layers) == 0 {
		logger.Fatalf("Could not read Docker image layers: no layers can be found")
	}
	return manifest
}
