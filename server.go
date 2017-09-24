package main

import (
	"net/http"
	"time"
)

const (
	httpPort = "9279"
)

// httpFileServer servers files from a specified folder
// TODO if port can't be opened is not handled
func httpFileServer(path string) *http.Server {
	server := &http.Server{Addr: ":" + httpPort}
	http.Handle("/", http.FileServer(http.Dir(path)))
	go func() {
		server.ListenAndServe()
	}()
	time.Sleep(100 * time.Millisecond) // It takes some time to open the port, just to be sure we wait a bit
	logger.Infof("Server listening on port %s", httpPort)
	return server
}
