package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

var httpPort = "9279"

type Logger interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// httpFileServer starts an HTTP file server at a specified path.
func httpFileServer(path string, logger Logger, listenAndServe func(*http.Server) error, timeout time.Duration) (*http.Server, error) {
	// Validate that the directory exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.Errorf("Path does not exist: %s", path)
		return nil, fmt.Errorf("path does not exist: %s", path)
	}

	// Configure the HTTP server
	server := &http.Server{
		Addr:    "0.0.0.0:" + httpPort,
		Handler: http.FileServer(http.Dir(path)),
	}

	errChan := make(chan error, 1)

	go func() {
		logger.Infof("Starting HTTP file server on %s serving path: %s", server.Addr, path)
		errChan <- listenAndServe(server)
	}()

	start := time.Now()
	for {
		select {
		case err := <-errChan:
			if err != nil {
				logger.Errorf("Error starting HTTP server: %v", err)
				return nil, err
			}
		default:
			resp, err := http.Get("http://localhost:" + httpPort)
			if err == nil && resp.StatusCode == http.StatusOK {
				logger.Infof("HTTP server is ready on %s", server.Addr)
				return server, nil
			}
		}

		if time.Since(start) > timeout {
			logger.Errorf("Timeout waiting for server to start on port %s", httpPort)
			return nil, fmt.Errorf("timeout waiting for server to start on port %s", httpPort)
		}

		time.Sleep(500 * time.Millisecond)
	}
}
