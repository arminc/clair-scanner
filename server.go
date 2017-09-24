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
		server.ListenAndServe()
	}()
	time.Sleep(100 * time.Millisecond)
	logger.Infof("Server listening on port %s", httpPort)
	return server
}
