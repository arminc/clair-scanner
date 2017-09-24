package main

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func TestSigint(t *testing.T) {
	testListenOnSignal(t, syscall.SIGINT)
}

func testListenOnSignal(t *testing.T, testSignal syscall.Signal) {
	done := make(chan bool)

	go listenForSignal(func(signal os.Signal) {
		if signal != testSignal {
			t.Errorf("Expected signal %s, but got %s", testSignal, signal)
		}
		done <- true
	})

	time.AfterFunc(10*time.Millisecond, func() {
		syscall.Kill(syscall.Getpid(), testSignal)
	})
	<-done
}
