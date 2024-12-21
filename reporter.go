package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/mbndr/logo"
	"github.com/olekukonko/tablewriter"
)

type vulnerabilityReport struct {
	Image           string              `json:"image"`
	Unapproved      []string            `json:"unapproved"`
	Vulnerabilities []vulnerabilityInfo `json:"vulnerabilities"`
}

func sortBySeverity(vulnerabilities []vulnerabilityInfo) {
	sort.Slice(vulnerabilities, func(i, j int) bool {
		return SeverityMap[vulnerabilities[i].Severity] > SeverityMap[vulnerabilities[j].Severity]
	})
}

func formatStatus(status string) string {
	if status == "Approved" {
		return fmt.Sprintf(NoticeColor, status)
	}
	return fmt.Sprintf(ErrorColor, status)
}

func formatTableData(vulnerabilities []vulnerabilityInfo, unapproved []string) [][]string {
	formatted := make([][]string, len(vulnerabilities))
	for i, vulnerability := range vulnerabilities {
		status := "Approved"
		for _, u := range unapproved {
			if vulnerability.Vulnerability == u {
				status = "Unapproved"
			}
		}
		formatted[i] = []string{
			formatStatus(status),
			vulnerability.Severity + " " + vulnerability.Vulnerability,
			vulnerability.FeatureName,
			vulnerability.FeatureVersion,
			vulnerability.Description + "\n\n" + vulnerability.Link,
		}
	}
	return formatted
}

func printTable(writer io.Writer, vulnerabilities []vulnerabilityInfo, unapproved []string) {
	header := []string{"Status", "CVE Severity", "Package Name", "Package Version", "CVE Description"}
	table := tablewriter.NewWriter(writer)
	table.SetHeader(header)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetRowSeparator("-")
	table.SetRowLine(true)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.AppendBulk(formatTableData(vulnerabilities, unapproved))
	table.Render()
}

func filterApproved(vulnerabilities []vulnerabilityInfo, unapproved []string, reportAll bool) []vulnerabilityInfo {
	if reportAll {
		return vulnerabilities
	}

	vulns := make([]vulnerabilityInfo, 0)
	for _, vuln := range vulnerabilities {
		for _, u := range unapproved {
			if vuln.Vulnerability == u {
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns
}

func reportToConsole(logger *logo.Logger, writer io.Writer, imageName string, vulnerabilities []vulnerabilityInfo, unapproved []string, reportAll bool, quiet bool) {
	if quiet {
		return
	}

	if len(vulnerabilities) > 0 {
		logger.Warnf("Image [%s] contains %d total vulnerabilities", imageName, len(vulnerabilities))

		vulnerabilities = filterApproved(vulnerabilities, unapproved, reportAll)
		sortBySeverity(vulnerabilities)

		if len(unapproved) > 0 {
			logger.Errorf("Image [%s] contains %d unapproved vulnerabilities", imageName, len(unapproved))
			printTable(writer, vulnerabilities, unapproved)
		} else {
			logger.Infof("Image [%s] contains NO unapproved vulnerabilities", imageName)
			if reportAll {
				printTable(writer, vulnerabilities, unapproved)
			}
		}
	} else {
		logger.Infof("Image [%s] contains NO unapproved vulnerabilities", imageName)
	}
}

func reportToFile(imageName string, vulnerabilities []vulnerabilityInfo, unapproved []string, file string) ([]byte, error) {
	if file == "" {
		return nil, nil
	}
	report := &vulnerabilityReport{
		Image:           imageName,
		Vulnerabilities: vulnerabilities,
		Unapproved:      unapproved,
	}
	reportJSON, err := json.MarshalIndent(report, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("could not create a report: report is not proper JSON %v", err)
	}
	return reportJSON, nil
}
