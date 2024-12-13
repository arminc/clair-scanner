package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/mbndr/logo"
)

// MockHTTPClient mocks the HTTPClient interface for testing
type MockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	return nil, errors.New("DoFunc not implemented")
}

// createMockTar creates a valid tar archive for testing
func createMockTar() ([]byte, error) {
	// Create an in-memory tar archive
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Add a dummy file to the tar archive
	err := tw.WriteHeader(&tar.Header{
		Name: "dummy.txt",
		Mode: 0600,
		Size: int64(len("dummy content")),
	})
	if err != nil {
		return nil, err
	}

	_, err = tw.Write([]byte("dummy content"))
	if err != nil {
		return nil, err
	}

	// Close the tar writer to finish writing the archive
	err = tw.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func TestScan(t *testing.T) {
	logger = logo.NewLogger(logo.NewReceiver(os.Stdout, ""))
	dockerClient := &MockDockerClient{
		ImageSaveFunc: func(ctx context.Context, imageIDs []string) (io.ReadCloser, error) {
			// Generate a valid tar archive
			tarData, err := createMockTar()
			if err != nil {
				return nil, err
			}
			return io.NopCloser(bytes.NewReader(tarData)), nil
		},
	}

	fileSystem := &MockFileSystem{
		ReadFileFunc: func(name string) ([]byte, error) {
			if strings.Contains(name, "index.json") {
				return []byte(`{"manifests":[{"digest":"sha256:testdigest"}]}`), nil
			}
			if strings.Contains(name, "blobs/sha256/testdigest") {
				return []byte(`{"layers":[{"digest":"sha256:layer1"}]}`), nil
			}
			return nil, errors.New("file not found")
		},
		StatFunc: func(name string) (os.FileInfo, error) {
			// Simulate file existence
			return &mockFileInfo{}, nil
		},
	}

	httpClient := &MockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Simulate expected responses for specific endpoints
			if req.URL.Path == "/indexer/api/v1/index_report" {
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewReader([]byte(`{"manifest_hash":"dummy_report_id"}`))),
				}, nil
			}
			if req.URL.Path == "/indexer/api/v1/index_report/dummy_report_id" {
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
				}, nil
			}
			if req.URL.Path == "/matcher/api/v1/vulnerability_report/dummy_report_id" {
				return &http.Response{
					StatusCode: 200,
					Body: io.NopCloser(bytes.NewReader([]byte(`{
						"vulnerabilities": {
							"CVE-1234": {
								"name": "CVE-1234",
								"severity": "High",
								"description": "Test vulnerability",
								"package": {"name": "test-package", "version": "1.0"},
								"links": "http://example.com"
							},
							"CVE-5678": {
								"name": "CVE-5678",
								"severity": "Medium"
							}
						}
					}`))),
				}, nil
			}

			// Default case for unexpected requests
			return nil, fmt.Errorf("unexpected request to URL: %s", req.URL.String())
		},
	}

	scanner := NewDefaultScanner(dockerClient, fileSystem, httpClient)

	config := ScannerConfig{
		ImageName: "test-image",
		Whitelist: vulnerabilitiesWhitelist{
			GeneralWhitelist: map[string]string{"CVE-1234": "Test CVE"},
			Images:           map[string]map[string]string{"test-image": {"CVE-5678": "Another Test CVE"}},
		},
		ClairURL:           "http://clair-url",
		ScannerIP:          "localhost",
		ReportFile:         "report.txt",
		WhitelistThreshold: "High",
		ReportAll:          true,
		Quiet:              false,
		ExitWhenNoFeatures: false,
	}

	unapproved := scanner.Scan(config)

	if len(unapproved) > 0 {
		t.Errorf("Expected no unapproved vulnerabilities, got %v", unapproved)
	}
}
