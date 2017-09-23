package main

import (
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// listenForSignal listens for interaptions and exectus the desired code when it happens
func listenForSignal(fn func(os.Signal)) {
	signalChannel := make(chan os.Signal)

	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGQUIT)

	for {
		execute := <-signalChannel
		fn(execute)
	}
}

// createTmpPath creates an temporary folder with an prefix
func createTmpPath(tmpPrefix string) string {
	tmpPath, err := ioutil.TempDir("", tmpPrefix)
	if err != nil {
		log.Fatalf("Could not create temporary folder: %s", err)
	}
	return tmpPath
}
