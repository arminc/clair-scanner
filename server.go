package main

import (
	"net/http"
	"time"
)

const (
	httpPort = "9279"
)

// TODO make a test
func httpFileServer(path string) *http.Server {
	server := &http.Server{Addr: ":" + httpPort}
	http.Handle("/", http.FileServer(http.Dir(path)))
	go func() {
		if err := server.ListenAndServe(); err != nil {
			Logger.Fatalf("An error occurred when starting HTTP server: %s", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	Logger.Info("Server listening on port %s", httpPort)
	return server
}
