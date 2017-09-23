package main

import (
	"log"
	"net/http"
	"time"
)

// TODO make a test
func httpFileServer(path string, port string) *http.Server {
	server := &http.Server{Addr: ":" + port}
	http.Handle("/", http.FileServer(http.Dir(path)))
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("An error occurred when starting HTTP server: %s", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	log.Printf("Server listening on port %s", port)
	return server
}
