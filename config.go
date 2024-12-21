package main

import cli "github.com/jawher/mow.cli"

type AppConfig struct {
	WhitelistFile      string
	WhitelistThreshold string
	ClairURL           string
	IP                 string
	LogFile            string
	ReportAll          bool
	ReportFile         string
	Quiet              bool
	ImageName          string
	ExitWhenNoFeatures bool
	Whitelist          vulnerabilitiesWhitelist
}

func (cfg *AppConfig) RegisterOptions(app *cli.Cli) {
	cfg.WhitelistFile = *app.StringOpt("w whitelist", "", "Path to the whitelist file")
	cfg.WhitelistThreshold = *app.StringOpt("t threshold", "Unknown", "CVE severity threshold")
	cfg.ClairURL = *app.StringOpt("c clair", "http://127.0.0.1:6060", "Clair URL")
	cfg.IP = *app.StringOpt("ip", "localhost", "IP address where clair-scanner is running on")
	cfg.LogFile = *app.StringOpt("l log", "", "Log to a file")
	cfg.ReportAll = *app.BoolOpt("all reportAll", true, "Display all vulnerabilities, even if approved")
	cfg.ReportFile = *app.StringOpt("r report", "", "Report output file, as JSON")
	cfg.Quiet = *app.BoolOpt("q quiet", false, "Quiets ASCII table output")
	cfg.ImageName = *app.StringArg("IMAGE", "", "Name of the Docker image to scan")
	cfg.ExitWhenNoFeatures = *app.BoolOpt("exit-when-no-features", false, "Exit with status code 5 when no features are found")
}

func (cfg *AppConfig) ScannerConfig() ScannerConfig {
	return ScannerConfig{
		ImageName:          cfg.ImageName,
		Whitelist:          cfg.Whitelist,
		ClairURL:           cfg.ClairURL,
		ScannerIP:          cfg.IP,
		ReportFile:         cfg.ReportFile,
		WhitelistThreshold: cfg.WhitelistThreshold,
		ReportAll:          cfg.ReportAll,
		Quiet:              cfg.Quiet,
		ExitWhenNoFeatures: cfg.ExitWhenNoFeatures,
	}
}
