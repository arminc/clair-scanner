package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/arminc/clair-scanner/pkg/types"
	"github.com/docker/docker/client"
)

// DockerClient defines the methods used from the Docker API
type DockerClient interface {
	ImageSave(ctx context.Context, imageIDs []string) (io.ReadCloser, error)
}

// RealDockerClient implements DockerClient using the Docker API
type RealDockerClient struct {
	cli *client.Client
}

func NewRealDockerClient() (*RealDockerClient, error) {
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}
	return &RealDockerClient{cli: cli}, nil
}

func (r *RealDockerClient) ImageSave(ctx context.Context, imageIDs []string) (io.ReadCloser, error) {
	return r.cli.ImageSave(ctx, imageIDs)
}

// FileSystem defines file operations for testability
type FileSystem interface {
	ReadFile(name string) ([]byte, error)
	Open(name string) (*os.File, error)
	Stat(name string) (os.FileInfo, error)
}

// RealFileSystem implements FileSystem with os package
type RealFileSystem struct{}

func (fs RealFileSystem) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (fs RealFileSystem) Open(name string) (*os.File, error) {
	return os.Open(name)
}

func (fs RealFileSystem) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

// saveDockerImage saves Docker image to temporary folder
func saveDockerImage(docker DockerClient, imageName, tmpPath string) error {
	imageReader, err := docker.ImageSave(context.Background(), []string{imageName})
	if err != nil {
		return fmt.Errorf("could not save Docker image [%s]: %w", imageName, err)
	}
	defer imageReader.Close()

	if err := untar(imageReader, tmpPath); err != nil {
		return fmt.Errorf("could not untar Docker image [%s]: %w", imageName, err)
	}
	return nil
}

// LoadDockerManifest processes a Docker manifest from a directory
func LoadDockerManifest(folderPath string, scannerIP string, fs FileSystem) (*types.Payload, error) {
	indexFilePath := filepath.Join(folderPath, "index.json")

	indexData, err := fs.ReadFile(indexFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading index.json: %w", err)
	}

	var dockerData types.DockerData
	if err = json.Unmarshal(indexData, &dockerData); err != nil {
		return nil, fmt.Errorf("error unmarshaling index.json: %w", err)
	}

	if len(dockerData.Manifests) == 0 {
		return nil, fmt.Errorf("index.json contains no manifests")
	}

	manifestDigest := strings.TrimPrefix(dockerData.Manifests[0].Digest, "sha256:")
	blobsPath := filepath.Join(folderPath, "blobs", "sha256")
	manifestFilePath := filepath.Join(blobsPath, manifestDigest)

	if _, err = fs.Stat(manifestFilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("manifest file not found: %s", manifestFilePath)
	}

	manifestDataBytes, err := fs.ReadFile(manifestFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading manifest file: %w", err)
	}

	var manifestData types.ManifestData
	if err = json.Unmarshal(manifestDataBytes, &manifestData); err != nil {
		return nil, fmt.Errorf("error unmarshaling manifest file: %w", err)
	}

	var layers []types.LayerURI
	for _, layer := range manifestData.Layers {
		layerDigest := strings.TrimPrefix(layer.Digest, "sha256:")
		layerPath := filepath.Join(blobsPath, layerDigest)

		if _, err = fs.Stat(layerPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("layer file %s does not exist", layerPath)
		}

		layerURI := types.LayerURI{
			Hash: layer.Digest,
			URI:  fmt.Sprintf("http://%s:%s/blobs/sha256/%s", scannerIP, "80", layerDigest),
		}
		layers = append(layers, layerURI)
	}

	return &types.Payload{
		Hash:   fmt.Sprintf("sha256:%s", manifestDigest),
		Layers: layers,
	}, nil
}
