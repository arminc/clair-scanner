package main

import (
	"archive/tar"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	yaml "gopkg.in/yaml.v2"
)

// listenForSignal listens for interactions and executes the desired code when it happens
func listenForSignal(fn func(os.Signal)) {
	signalChannel := make(chan os.Signal)

	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGQUIT)

	for {
		execute := <-signalChannel
		fn(execute)
	}
}

// createTmpPath creates a temporary folder with a prefix
func createTmpPath(tmpPrefix string) string {
	tmpPath, err := ioutil.TempDir("", tmpPrefix)
	if err != nil {
		logger.Fatalf("Could not create temporary folder: %s", err)
	}
	return tmpPath
}

// untar uses a Reader that represents a tar to untar it on the fly to a target folder
func untar(imageReader io.ReadCloser, target string) error {
	tarReader := tar.NewReader(imageReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		path := filepath.Join(target, header.Name)
		info := header.FileInfo()
		if info.IsDir() {
			if err = os.MkdirAll(path, info.Mode()); err != nil {
				return err
			}
			continue
		}

		file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err = io.Copy(file, tarReader); err != nil {
			return err
		}
	}
	return nil
}

// parseWhitelistFile reads the whitelist file and parses it
func parseWhitelistFile(whitelistFile string) vulnerabilitiesWhitelist {
	whitelistTmp := vulnerabilitiesWhitelist{}

	whitelistBytes, err := ioutil.ReadFile(whitelistFile)
	if err != nil {
		logger.Fatalf("Could not parse whitelist file, could not read file %v", err)
	}
	if err = yaml.Unmarshal(whitelistBytes, &whitelistTmp); err != nil {
		logger.Fatalf("Could not parse whitelist file, could not unmarshal %v", err)
	}
	return whitelistTmp
}
