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

type manifestJson struct {
	Layers []string
}

// saveDockerImage saves Docker image to temorary folder
func saveDockerImage(imageName string, tmpPath string) error {
	docker := createDockerClient()

	imageReader, err := docker.ImageSave(context.Background(), []string{imageName})
	if err != nil {
		Logger.Fatalf("Could not save Docker image [%v] : %v", imageName, err)
	}

	defer imageReader.Close()
	return untar(imageReader, tmpPath)
}

func createDockerClient() client.APIClient {
	docker, err := client.NewEnvClient()
	if err != nil {
		Logger.Fatalf("Could not create a Docker client: %v", err)
	}
	return docker
}

// TODO make a test
func getImageLayerIds(path string) []string {
	manifest := readManifestFile(path)

	var layers []string
	for _, layer := range manifest[0].Layers {
		layers = append(layers, strings.TrimSuffix(layer, "/layer.tar"))
	}
	return layers
}

func readManifestFile(path string) []manifestJson {
	manifestFile := path + "/manifest.json"
	mf, err := os.Open(manifestFile)
	if err != nil {
		Logger.Fatalf("Could not read Docker image layers, could not open [%v]: %v", manifestFile, err)
	}
	defer mf.Close()

	return parseAndValidateManifestFile(mf)
}

func parseAndValidateManifestFile(manifestFile io.Reader) []manifestJson {
	var manifest []manifestJson
	if err := json.NewDecoder(manifestFile).Decode(&manifest); err != nil {
		Logger.Fatalf("Could not read Docker image layers, manifest.json is not json: %v", err)
	} else if len(manifest) != 1 {
		Logger.Fatalf("Could not read Docker image layers, manifest.json is not valid")
	} else if len(manifest[0].Layers) == 0 {
		Logger.Fatalf("Could not read Docker image layers, no layers can be found")
	}
	return manifest
}
