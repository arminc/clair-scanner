package main

import (
	"log"
	"os"

	cli "github.com/jawher/mow.cli"
)

const (
	tmpPrefix           = "clair-scanner-"
	postLayerURI        = "/v1/layers"
	getLayerFeaturesURI = "/v1/layers/%s?vulnerabilities"
)

var (
	whitelist = vulnerabilitiesWhitelist{}
)

func main() {
	app := cli.App("clair-scanner", "Scan local Docker images for vulnerabilities with Clair")

	var (
		whitelistFile = app.StringOpt("w whitelist", "", "Path to the whitelist file")
		clair         = app.StringOpt("c clair", "http://127.0.0.1:6060", "Clair url")
		ip            = app.StringOpt("ip", "localhost", "IP addres where clair-scanner is running on")
		imageName     = app.StringArg("IMAGE", "", "Name of the Docker image to scan")
	)

	app.Before = func() {
		if *whitelistFile != "" {
			whitelist = parseWhitelistFile(*whitelistFile)
		}
	}

	app.Action = func() {
		log.Print("Start clair-scanner")

		go listenForSignal(func(s os.Signal) {
			log.Fatalf("Application interupted [%v]", s)
		})

		scan(*imageName, whitelist, *clair, *ip)
	}
	app.Run(os.Args)
}
