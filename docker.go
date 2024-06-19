package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/client"
)

// DockerData represents the structure of the manifest data
type DockerData struct {
	Manifests []struct {
		Digest string `json:"digest"`
	} `json:"manifests"`
}

// ManifestData represents the structure of a manifest file
type ManifestData struct {
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

// LayerURI contains information about a layer
type LayerURI struct {
	Hash string `json:"hash"`
	URI  string `json:"uri"`
}

// Payload is used to prepare data for Clair Indexer
type Payload struct {
	Hash   string     `json:"hash"`
	Layers []LayerURI `json:"layers"`
}

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

// LoadDockerManifest processes a Docker manifest from a directory
func LoadDockerManifest(folderPath string, scannerIP string) (*Payload, error) {
	indexFilePath := filepath.Join(folderPath, "index.json")
	log.Printf("Loading the index.json file from %s...", indexFilePath)

	indexData, err := os.ReadFile(indexFilePath)
	if err != nil {
		log.Printf("Error reading index.json: %s", err)
		return nil, err
	}

	var dockerData DockerData
	if err = json.Unmarshal(indexData, &dockerData); err != nil {
		log.Printf("Error unmarshaling index.json: %s", err)
		return nil, err
	}

	manifestDigest := dockerData.Manifests[0].Digest
	manifestDigest = manifestDigest[len("sha256:"):]

	blobsPath := filepath.Join(folderPath, "blobs", "sha256")
	manifestFilePath := filepath.Join(blobsPath, manifestDigest)
	if _, err = os.Stat(manifestFilePath); os.IsNotExist(err) {
		log.Printf("Manifest file not found: %s", manifestFilePath)
		return nil, err
	}

	log.Printf("Loading the manifest file from %s...", manifestFilePath)
	manifestDataBytes, err := os.ReadFile(manifestFilePath)
	if err != nil {
		log.Printf("Error reading the manifest file: %s", err)
		return nil, err
	}

	var manifestData ManifestData
	if err = json.Unmarshal(manifestDataBytes, &manifestData); err != nil {
		log.Printf("Error unmarshaling the manifest file: %s", err)
		return nil, err
	}

	var layers []LayerURI
	for _, layer := range manifestData.Layers {
		layerDigest := layer.Digest[len("sha256:"):]
		layerPath := filepath.Join(blobsPath, layerDigest)
		if _, err = os.Stat(layerPath); os.IsNotExist(err) {
			log.Printf("Layer file %s does not exist", layerPath)
			return nil, err
		}
		layerURI := LayerURI{
			Hash: layer.Digest,
			URI:  fmt.Sprintf("http://%s:%s/blobs/sha256/%s", scannerIP, httpPort, layerDigest),
		}
		layers = append(layers, layerURI)
	}

	payload := &Payload{
		Hash:   fmt.Sprintf("sha256:%s", manifestDigest),
		Layers: layers,
	}

	return payload, nil
}
