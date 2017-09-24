package main

import (
	"fmt"
	"log"
	"os"

	cli "github.com/jawher/mow.cli"
	"github.com/mbndr/logo"
)

const (
	tmpPrefix           = "clair-scanner-"
	postLayerURI        = "/v1/layers"
	getLayerFeaturesURI = "/v1/layers/%s?vulnerabilities"
)

var (
	whitelist = vulnerabilitiesWhitelist{}
	Logger    *logo.Logger
)

func main() {
	app := cli.App("clair-scanner", "Scan local Docker images for vulnerabilities with Clair")

	var (
		whitelistFile = app.StringOpt("w whitelist", "", "Path to the whitelist file")
		clair         = app.StringOpt("c clair", "http://127.0.0.1:6060", "Clair url")
		ip            = app.StringOpt("ip", "localhost", "IP addres where clair-scanner is running on")
		logFile       = app.StringOpt("l log", "", "Log to a file")
		imageName     = app.StringArg("IMAGE", "", "Name of the Docker image to scan")
	)

	app.Before = func() {
		logger(*logFile)
		if *whitelistFile != "" {
			whitelist = parseWhitelistFile(*whitelistFile)
		}
	}

	app.Action = func() {
		Logger.Info("Start clair-scanner")

		go listenForSignal(func(s os.Signal) {
			log.Fatalf("Application interupted [%v]", s)
		})

		scan(*imageName, whitelist, *clair, *ip)
	}
	app.Run(os.Args)
}

func logger(logFile string) {
	cliRec := logo.NewReceiver(os.Stderr, "")
	cliRec.Color = true

	if logFile != "" {
		file, err := logo.Open(logFile)
		if err != nil {
			fmt.Printf("Could not initialize logging file %v", err)
			os.Exit(1)
		}

		fileRec := logo.NewReceiver(file, "")
		Logger = logo.NewLogger(cliRec, fileRec)
	} else {
		Logger = logo.NewLogger(cliRec)
	}
}
