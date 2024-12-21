package main

import (
	"os"
	"testing"

	cli "github.com/jawher/mow.cli"
	"github.com/stretchr/testify/assert"
)

func TestSetupApp(t *testing.T) {
	// Mock CLI args
	os.Args = []string{
		"clair-scanner",
		"--clair=http://localhost:8080",
		"--threshold=High",
		"--report=clair_report.json",
		"test-image",
	}

	// Initialize ScannerApp
	scannerApp := &ScannerApp{}
	scannerApp.Run = func(config ScannerConfig) {
		// Assertions to verify the config
		assert.Equal(t, "test-image", config.ImageName, "Image name should match CLI argument")
		assert.Equal(t, "http://localhost:8080", config.ClairURL, "Clair URL should match CLI argument")
		assert.Equal(t, "High", config.WhitelistThreshold, "Threshold should match CLI argument")
		assert.Equal(t, "clair_report.json", config.ReportFile, "Report file should match CLI argument")
	}

	// Create the CLI app
	app := cli.App("clair-scanner", "Test CLI setup")
	setupApp(app, scannerApp)

	// Mock os.Exit
	var exitCode int
	osExit = func(code int) { exitCode = code }
	defer func() { osExit = os.Exit }() // Restore os.Exit after the test

	// Run the CLI app to parse arguments and trigger actions
	app.Run(os.Args)

	// Verify results
	assert.Equal(t, 0, exitCode, "Expected exit code 0")
	assert.NotNil(t, scannerApp.Logger, "Logger should be initialized")
	assert.True(t, scannerApp.Whitelist.IsEmpty(), "Whitelist should be empty")
}
