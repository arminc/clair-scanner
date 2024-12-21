package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestSaveDockerImage_Success(t *testing.T) {
	// Create a mock tarball with valid format
	tarData := new(bytes.Buffer)
	tw := tar.NewWriter(tarData)
	if err := tw.Close(); err != nil {
		t.Fatalf("Error creating mock tar data: %v", err)
	}

	mockDocker := &MockDockerClient{
		ImageSaveFunc: func(ctx context.Context, imageIDs []string) (io.ReadCloser, error) {
			// Return the mock tar data
			return io.NopCloser(bytes.NewReader(tarData.Bytes())), nil
		},
	}

	err := saveDockerImage(mockDocker, "test-image", "/tmp")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
}

func TestSaveDockerImage_Error(t *testing.T) {
	mockDocker := &MockDockerClient{
		ImageSaveFunc: func(ctx context.Context, imageIDs []string) (io.ReadCloser, error) {
			// Simulate error during image save
			return nil, errors.New("mock error")
		},
	}

	err := saveDockerImage(mockDocker, "test-image", "/tmp")
	if err == nil || err.Error() != "could not save Docker image [test-image]: mock error" {
		t.Fatalf("Expected specific error, got: %v", err)
	}
}

func TestLoadDockerManifest_MissingIndexFile(t *testing.T) {
	mockFS := MockFileSystem{
		ReadFileFunc: func(name string) ([]byte, error) {
			// Simulate missing file
			return nil, errors.New("file not found")
		},
	}

	_, err := LoadDockerManifest("/fake/path", "127.0.0.1", mockFS)
	if err == nil || err.Error() != "error reading index.json: file not found" {
		t.Fatalf("Expected error for missing index.json, got: %v", err)
	}
}

func TestLoadDockerManifest_InvalidJSON(t *testing.T) {
	mockFS := MockFileSystem{
		ReadFileFunc: func(name string) ([]byte, error) {
			// Simulate invalid JSON content
			return []byte("invalid json"), nil
		},
	}

	_, err := LoadDockerManifest("/fake/path", "127.0.0.1", mockFS)
	if err == nil || err.Error() != "error unmarshaling index.json: invalid character 'i' looking for beginning of value" {
		t.Fatalf("Expected error for invalid JSON, got: %v", err)
	}
}

func TestLoadDockerManifest_Success(t *testing.T) {
	mockFS := MockFileSystem{
		ReadFileFunc: func(name string) ([]byte, error) {
			if name == "/fake/path/index.json" {
				// Simulate valid index.json content
				return []byte(`{"manifests":[{"digest":"sha256:testdigest"}]}`), nil
			}
			if name == "/fake/path/blobs/sha256/testdigest" {
				// Simulate valid manifest.json content
				return []byte(`{"layers":[{"digest":"sha256:layer1"}]}`), nil
			}
			return nil, errors.New("file not found")
		},
		StatFunc: func(name string) (os.FileInfo, error) {
			// Simulate existing file
			return &mockFileInfo{}, nil
		},
	}

	payload, err := LoadDockerManifest("/fake/path", "127.0.0.1", mockFS)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if payload.Hash != "sha256:testdigest" {
		t.Errorf("Expected payload.Hash to be 'sha256:testdigest', got: %s", payload.Hash)
	}

	if len(payload.Layers) != 1 || payload.Layers[0].Hash != "sha256:layer1" {
		t.Errorf("Expected one layer with hash 'sha256:layer1', got: %+v", payload.Layers)
	}
}

// mockFileInfo is a mock implementation of os.FileInfo
type mockFileInfo struct{}

func (m *mockFileInfo) Name() string       { return "mockFile" }
func (m *mockFileInfo) Size() int64        { return 0 }
func (m *mockFileInfo) Mode() os.FileMode  { return 0 }
func (m *mockFileInfo) ModTime() time.Time { return time.Now() }
func (m *mockFileInfo) IsDir() bool        { return false }
func (m *mockFileInfo) Sys() interface{}   { return nil }
