//go:build integration
// +build integration

package main

import (
	"flag"
	"os"
	"testing"
)

var (
	ip = flag.String("ip", "localhost", "scanner ip")
)

func TestMain(m *testing.M) {
	flag.Parse()
	result := m.Run()
	os.Exit(result)
}

func TestDebian(t *testing.T) {
	initializeLogger("")
	unapproved := scan(scannerConfig{
		"debian:bookworm",
		vulnerabilitiesWhitelist{},
		"http://127.0.0.1:8080",
		*ip,
		"",
		"Unknown",
		true,
		false,
		true,
	})
	if len(unapproved) == 0 {
		t.Errorf("No vulnerabilities, expecting some")
	}
}
