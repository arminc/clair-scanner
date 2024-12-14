package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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

func TestHttpFileServer(t *testing.T) {
	t.Run("starts server successfully", func(t *testing.T) {
		mockLogger := &MockLogger{}
		testPath := t.TempDir() // Creates a temporary directory for testing

		// Create a real HTTP test server to simulate server readiness
		ts := httptest.NewServer(http.FileServer(http.Dir(testPath)))
		defer ts.Close()

		// Extract the port from the test server URL
		port := ts.Listener.Addr().(*net.TCPAddr).Port
		httpPort = fmt.Sprintf("%d", port) // Override the port globally for the test

		// Mock the listenAndServe function
		listenAndServe := func(server *http.Server) error {
			return nil // Simulate successful server start
		}

		server, err := httpFileServer(testPath, mockLogger, listenAndServe, 2*time.Second)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if server == nil {
			t.Fatalf("expected server to be returned, got nil")
		}

		// Validate logs
		if len(mockLogger.infoMessages) == 0 {
			t.Errorf("expected info logs, got none")
		}
	})

	t.Run("returns error when path does not exist", func(t *testing.T) {
		mockLogger := &MockLogger{}
		invalidPath := "/nonexistentpath"

		listenAndServe := func(server *http.Server) error {
			return nil
		}

		_, err := httpFileServer(invalidPath, mockLogger, listenAndServe, 2*time.Second)
		if err == nil {
			t.Fatalf("expected error for nonexistent path, got nil")
		}

		// Validate error logs
		if len(mockLogger.errorMessages) == 0 {
			t.Errorf("expected error logs, got none")
		}
	})

	t.Run("returns error when server fails to start", func(t *testing.T) {
		mockLogger := &MockLogger{}
		testPath := t.TempDir()

		// Mock the listenAndServe function to return an error
		listenAndServe := func(server *http.Server) error {
			return errors.New("mock server start error")
		}

		_, err := httpFileServer(testPath, mockLogger, listenAndServe, 2*time.Second)
		if err == nil {
			t.Fatalf("expected error when server fails to start, got nil")
		}

		// Validate error logs
		if len(mockLogger.errorMessages) == 0 {
			t.Errorf("expected error logs, got none")
		}
	})

	t.Run("times out when server does not become ready", func(t *testing.T) {
		mockLogger := &MockLogger{}
		testPath := t.TempDir()

		// Set a unique test port
		httpPort = "41731"

		// Mock the listenAndServe function to simulate a delay
		listenAndServe := func(server *http.Server) error {
			time.Sleep(5 * time.Second) // Simulates server never becoming ready within the test timeout
			return nil
		}

		// Use a short timeout for testing
		_, err := httpFileServer(testPath, mockLogger, listenAndServe, 2*time.Second)
		if err == nil {
			t.Fatalf("expected timeout error, got nil")
		}

		// Validate the error message
		expectedError := fmt.Sprintf("timeout waiting for server to start on port %s", httpPort)
		if err.Error() != expectedError {
			t.Fatalf("expected error %q, got %q", expectedError, err.Error())
		}

		// Validate error logs
		if len(mockLogger.errorMessages) == 0 {
			t.Errorf("expected error logs, got none")
		}
	})
}
