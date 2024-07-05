package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/docker/docker/client"
)

// TODO Add support for older version of docker

type manifestJSON struct {
	Layers []string
}

type newManifestJSON struct {
	Layers []newManifestJSONDigest `json:"layers"`
}

type newManifestJSONDigest struct {
	Digest string `json:"digest"`
}

// saveDockerImage saves Docker image to temorary folder
func saveDockerImage(imageName string, tmpPath string) {
	docker := createDockerClient()

	version, err := docker.ServerVersion(context.Background())
	if err != nil {
		logger.Fatalf("Could not find Docker version: %v", err)
	}
	majorVersion, err := strconv.Atoi(strings.Split(version.Version, ".")[0])
	if err != nil {
		logger.Fatalf("Error while parsing Docker version '%s': %v", version.Version, err)
	}
	if majorVersion < 25 {
		legacy = true
		imageReader, err := docker.ImageSave(context.Background(), []string{imageName})
		if err != nil {
			logger.Fatalf("Could not save Docker image [%s]: %v", imageName, err)
		}
		defer imageReader.Close()

		if err = untar(imageReader, tmpPath); err != nil {
			logger.Fatalf("Could not save Docker image: could not untar [%s]: %v", imageName, err)
		}
	} else {
		updateDockerImage(imageName, tmpPath)
	}
}

func updateDockerImage(imageName string, tmpPath string) {
	logger.Infof("Converting Docker image '%s' in '%s' to legacy format...", imageName, tmpPath)
	cmd := exec.Command(getEnv("SKOPEO_BIN_PATH", "skopeo"), "copy", "--format", "v2s2", fmt.Sprintf("docker-daemon:%s", imageName), fmt.Sprintf("dir:%s", tmpPath))
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	if errors.Is(cmd.Err, exec.ErrDot) {
		cmd.Err = nil
	}
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error running skopeo: %s %s", err, errb.String())
	}
	updateLegacyManifestFile(tmpPath)
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

// readManifestFile reads the local manifest.json
func updateLegacyManifestFile(path string) {
	manifestFile := path + "/manifest.json"
	mf, err := os.Open(manifestFile)
	if err != nil {
		logger.Fatalf("Could not read Docker image layers: could not open [%s]: %v", manifestFile, err)
	}
	defer mf.Close()

	var manifest newManifestJSON

	if err := json.NewDecoder(mf).Decode(&manifest); err != nil {
		logger.Fatalf("Could not read Docker image layers: manifest.json is not json: %v", err)
	}
	mf.Close()
	var legacyManifest []manifestJSON = []manifestJSON{
		{
			Layers: make([]string, len(manifest.Layers)),
		},
	}
	for i, v := range manifest.Layers {
		legacyManifest[0].Layers[i] = strings.TrimPrefix(v.Digest, "sha256:")
	}
	manifestFileContent, _ := json.MarshalIndent(legacyManifest, "", "  ")
	os.WriteFile(manifestFile, manifestFileContent, 0644)
}
