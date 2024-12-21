package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	cli "github.com/jawher/mow.cli"
	"github.com/mbndr/logo"
)

var osExit = os.Exit

type vulnerabilitiesWhitelist struct {
	GeneralWhitelist map[string]string            // [key: CVE and value: CVE description]
	Images           map[string]map[string]string // Image name with [key: CVE and value: CVE description]
}

// IsEmpty checks if the vulnerabilitiesWhitelist is empty
func (w vulnerabilitiesWhitelist) IsEmpty() bool {
	return (w.GeneralWhitelist == nil || len(w.GeneralWhitelist) == 0) &&
		(w.Images == nil || len(w.Images) == 0)
}

type ScannerApp struct {
	Logger    *logo.Logger
	Whitelist vulnerabilitiesWhitelist
	Run       func(config ScannerConfig) // Replaceable for testing
}

func main() {
	scannerApp := &ScannerApp{}
	scannerApp.Run = scannerApp.run // Default run implementation

	app := cli.App("clair-scanner", "Scan local Docker images for vulnerabilities with Clair")

	// Set up the CLI application
	setupApp(app, scannerApp)

	// Run the CLI application
	app.Run(os.Args)
}

func setupApp(app *cli.Cli, scannerApp *ScannerApp) {
	var (
		whitelistFile      = app.StringOpt("w whitelist", "", "Path to the whitelist file")
		whitelistThreshold = app.StringOpt("t threshold", "Unknown", "CVE severity threshold")
		clair              = app.String(cli.StringOpt{Name: "c clair", Value: "http://127.0.0.1:6060", Desc: "Clair URL", EnvVar: "CLAIR_URL"})
		ip                 = app.StringOpt("ip", "localhost", "IP address where clair-scanner is running on")
		logFile            = app.StringOpt("l log", "", "Log to a file")
		reportAll          = app.BoolOpt("all reportAll", true, "Display all vulnerabilities")
		reportFile         = app.StringOpt("r report", "", "Report output file, as JSON")
		quiet              = app.BoolOpt("q quiet", false, "Suppress ASCII table output")
		imageName          = app.StringArg("IMAGE", "", "Name of the Docker image to scan")
		exitWhenNoFeatures = app.BoolOpt("exit-when-no-features", false, "Exit with status code 5 when no features are found")
	)

	app.Before = func() {
		scannerApp.Logger = initializeLogger(*logFile)

		if *whitelistFile != "" {
			scannerApp.Whitelist = parseWhitelistFile(scannerApp.Logger, *whitelistFile)
		}

		validateThreshold(scannerApp.Logger, *whitelistThreshold)
	}

	app.Action = func() {
		config := ScannerConfig{
			Whitelist:          scannerApp.Whitelist,
			ClairURL:           *clair,
			ScannerIP:          *ip,
			ReportFile:         *reportFile,
			WhitelistThreshold: *whitelistThreshold,
			ReportAll:          *reportAll,
			Quiet:              *quiet,
			ExitWhenNoFeatures: *exitWhenNoFeatures,
			ImageName:          *imageName,
		}

		scannerApp.Run(config) // Call the replaceable Run function
	}
}

func (app *ScannerApp) run(config ScannerConfig) {
	if config.ImageName == "" {
		app.Logger.Error("Image name is required")
		osExit(1)
	}

	app.Logger.Infof("Starting clair-scanner for image: %s", config.ImageName)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigChan
		app.Logger.Warnf("Application interrupted [%v]", s)
		osExit(1)
	}()

	dockerClient, err := NewRealDockerClient()
	if err != nil {
		app.Logger.Errorf("Failed to create Docker client: %v", err)
		osExit(1)
	}

	scanner := NewDefaultScanner(dockerClient, RealFileSystem{}, &http.Client{})
	result := scanner.Scan(app.Logger, config)

	app.handleScanResult(result)
}

func (app *ScannerApp) handleScanResult(result []string) {
	if result == nil {
		app.Logger.Warn("No features found in the scanned image")
		osExit(5)
	} else if len(result) > 0 {
		app.Logger.Error("Unapproved vulnerabilities found in the image")
		osExit(1)
	}

	app.Logger.Info("Scan completed successfully with no vulnerabilities")
	osExit(0)
}

func initializeLogger(logFile string) *logo.Logger {
	cliRec := logo.NewReceiver(os.Stderr, "")
	cliRec.Color = true

	if logFile != "" {
		file, err := logo.Open(logFile)
		if err != nil {
			fmt.Printf("Could not initialize logging file: %v\n", err)
			osExit(1)
		}
		fileRec := logo.NewReceiver(file, "")
		return logo.NewLogger(cliRec, fileRec)
	}

	return logo.NewLogger(cliRec)
}
