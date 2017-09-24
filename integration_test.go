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

func TestAlpine(t *testing.T) {
	initializeLogger("")
	unapproved := scan(scannerConfig{"alpine:3.5", vulnerabilitiesWhitelist{}, "http://127.0.0.1:6060", *ip, ""})
	if len(unapproved) != 0 {
		t.Errorf("To many or no CVE's found, expected 0: [%s]", unapproved)
	}
}
