package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
)

// MockDockerClient is a mock implementation of DockerClient
type MockDockerClient struct {
	ImageSaveFunc func(ctx context.Context, imageIDs []string) (io.ReadCloser, error)
}

func (m *MockDockerClient) ImageSave(ctx context.Context, imageIDs []string) (io.ReadCloser, error) {
	return m.ImageSaveFunc(ctx, imageIDs)
}

// MockFileSystem is a mock implementation of FileSystem
// MockFileSystem is a mock implementation of FileSystem
type MockFileSystem struct {
	ReadFileFunc func(name string) ([]byte, error)
	StatFunc     func(name string) (os.FileInfo, error)
	OpenFunc     func(name string) (*os.File, error)
}

func (fs MockFileSystem) ReadFile(name string) ([]byte, error) {
	if fs.ReadFileFunc != nil {
		return fs.ReadFileFunc(name)
	}
	return nil, errors.New("ReadFile not implemented")
}

func (fs MockFileSystem) Stat(name string) (os.FileInfo, error) {
	if fs.StatFunc != nil {
		return fs.StatFunc(name)
	}
	return nil, errors.New("Stat not implemented")
}

func (fs MockFileSystem) Open(name string) (*os.File, error) {
	if fs.OpenFunc != nil {
		return fs.OpenFunc(name)
	}
	return nil, errors.New("Open not implemented")
}

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

// MockLogger is a mock implementation of the Logger interface for testing.
type MockLogger struct {
	infoMessages  []string
	errorMessages []string
}

func (m *MockLogger) Infof(format string, args ...interface{}) {
	m.infoMessages = append(m.infoMessages, format)
}

func (m *MockLogger) Errorf(format string, args ...interface{}) {
	m.errorMessages = append(m.errorMessages, format)
}
