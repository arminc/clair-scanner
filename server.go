package main

import (
	"net/http"
	"time"
)

const (
	httpPort = "9279"
)

type StatusRespWr struct {
	http.ResponseWriter // We embed http.ResponseWriter
	status              int
}

func (w *StatusRespWr) WriteHeader(status int) {
	w.status = status // Store the status for our own use
	w.ResponseWriter.WriteHeader(status)
}

// httpFileServer servers files from a specified folder
// TODO if port can't be opened is not handled
func httpFileServer(path string) *http.Server {
	server := &http.Server{Addr: ":" + httpPort, Handler: logRequest(http.DefaultServeMux)}
	http.Handle("/", http.FileServer(http.Dir(path)))
	go func() {
		server.ListenAndServe()
	}()
	time.Sleep(100 * time.Millisecond) // It takes some time to open the port, just to be sure we wait a bit
	logger.Infof("Server listening on port %s", httpPort)
	return server
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debugf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		srw := &StatusRespWr{ResponseWriter: w}
		handler.ServeHTTP(srw, r)
		if srw.status >= 400 { // 400+ codes are the error codes
			logger.Debugf("Error status code: %d when serving path: %s",
				srw.status, r.RequestURI)
		}

	})
}
