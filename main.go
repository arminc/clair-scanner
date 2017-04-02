package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/coreos/clair/api/v1"
	"github.com/docker/docker/client"
	"github.com/fatih/color"
)

const (
	scriptTerminatedByControlC = 130
	generalExit                = 0
	success                    = 0
	tmpPrefix                  = "clair-scanner-"
	httpPort                   = 9279
	postLayerURI               = "/v1/layers"
	getLayerFeaturesURI        = "/v1/layers/%s?vulnerabilities"
)

type vulnerabilityInfo struct {
	vulnerability string
	namespace     string
	severity      string
}

type acceptedVulnerability struct {
	Cve         string
	Description string
}

type vulnerabilitiesWhitelist struct {
	GeneralWhitelist map[string]string
	Images           map[string]map[string]string
}

func main() {
	flag.Parse()
	start(flag.Args()[0], parseWhitelist(flag.Args()[1]), flag.Args()[2], flag.Args()[3])
	os.Exit(success)
}

func parseWhitelist(whitelistFile string) vulnerabilitiesWhitelist {
	whitelist := vulnerabilitiesWhitelist{}
	whitelistBytes, err := ioutil.ReadFile(whitelistFile)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(whitelistBytes, &whitelist)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	return whitelist
}

func start(imageName string, whitelist vulnerabilitiesWhitelist, clairURL string, scannerIP string) {
	tmpPath := createTmpPath()
	defer os.RemoveAll(tmpPath)
	interrupt := make(chan os.Signal)
	signal.Notify(interrupt, os.Interrupt, os.Kill)

	analyzeCh := make(chan error, 1)
	go func() {
		analyzeCh <- analyzeImage(imageName, tmpPath, clairURL, scannerIP, whitelist)
	}()

	select {
	case <-interrupt:
		os.Exit(scriptTerminatedByControlC)
	case err := <-analyzeCh:
		if err != nil {
			os.Exit(generalExit)
		}
	}
}

func createTmpPath() string {
	tmpPath, err := ioutil.TempDir("", tmpPrefix)
	if err != nil {
		log.Fatalf("Could not create temporary folder: %s", err)
	}
	return tmpPath
}

func analyzeImage(imageName string, tmpPath string, clairURL string, scannerIP string, whitelist vulnerabilitiesWhitelist) error {
	err := saveImage(imageName, tmpPath)
	if err != nil {
		log.Printf("Could not save the image %s", err)
		return err
	}
	layerIds, err := getImageLayerIds(tmpPath)
	if err != nil {
		log.Printf("Could not read the image layer ids %s", err)
		return err
	}
	if err = analyzeLayers(layerIds, tmpPath, clairURL, scannerIP); err != nil {
		log.Printf("Analyzing faild: %s", err)
		return err
	}
	vulnerabilities, err := getVulnerabilities(clairURL, layerIds)
	if err != nil {
		log.Printf("Analyzing failed: %s", err)
		return err
	}
	err = vulnerabilitiesApproved(imageName, vulnerabilities, whitelist)
	if err != nil {
		log.Printf("Image contains unapproved vulnerabilities: %s", err)
		return err
	}
	return nil
}

func vulnerabilitiesApproved(imageName string, vulnerabilities []vulnerabilityInfo, whitelist vulnerabilitiesWhitelist) error {
	var unapproved []string
	imageVulnerabilities := getImageVulnerabilities(imageName, whitelist.Images)

	for i := 0; i < len(vulnerabilities); i++ {
		vulnerability := vulnerabilities[i].vulnerability
		vulnerable := true

		if _, exists := whitelist.GeneralWhitelist[vulnerability]; exists {
			vulnerable = false
		}
		if vulnerable && len(imageVulnerabilities) > 0 {
			if _, exists := imageVulnerabilities[vulnerability]; exists {
				vulnerable = false
			}
		}
		if vulnerable {
			unapproved = append(unapproved, vulnerability)
		}
	}
	if len(unapproved) > 0 {
		return fmt.Errorf("%s", unapproved)
	}
	return nil
}

func getImageVulnerabilities(imageName string, whitelistImageVulnerabilities map[string]map[string]string) map[string]string {
	var imageVulnerabilities map[string]string
	imageWithoutVersion := strings.Split(imageName, ":")
	if val, exists := whitelistImageVulnerabilities[imageWithoutVersion[0]]; exists {
		imageVulnerabilities = val
	}
	return imageVulnerabilities
}

func analyzeLayers(layerIds []string, tmpPath string, clairURL string, scannerIP string) error {
	ch := make(chan error)
	go listenHTTP(tmpPath, ch)
	select {
	case err := <-ch:
		return fmt.Errorf("An error occured when starting HTTP server: %s", err)
	case <-time.After(100 * time.Millisecond):
		break
	}

	tmpPath = "http://" + scannerIP + ":" + strconv.Itoa(httpPort)
	var err error

	for i := 0; i < len(layerIds); i++ {
		log.Printf("Analyzing %s\n", layerIds[i])

		if i > 0 {
			err = analyzeLayer(clairURL, tmpPath+"/"+layerIds[i]+"/layer.tar", layerIds[i], layerIds[i-1])
		} else {
			err = analyzeLayer(clairURL, tmpPath+"/"+layerIds[i]+"/layer.tar", layerIds[i], "")
		}
		if err != nil {
			return fmt.Errorf("Could not analyze layer: %s", err)
		}
	}
	return nil
}

func saveImage(imageName string, tmpPath string) error {
	docker := createDockerClient()
	imageID := []string{imageName}
	imageReader, err := docker.ImageSave(context.Background(), imageID)
	if err != nil {
		return err
	}

	defer imageReader.Close()
	return untar(imageReader, tmpPath)
}

func createDockerClient() *client.Client {
	docker, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}
	return docker
}

func getImageLayerIds(path string) ([]string, error) {
	mf, err := os.Open(path + "/manifest.json")
	if err != nil {
		return nil, err
	}
	defer mf.Close()

	// https://github.com/docker/docker/blob/master/image/tarexport/tarexport.go#L17
	type manifestItem struct {
		Config   string
		RepoTags []string
		Layers   []string
	}

	var manifest []manifestItem
	if err = json.NewDecoder(mf).Decode(&manifest); err != nil {
		return nil, err
	} else if len(manifest) != 1 {
		return nil, err
	}
	var layers []string
	for _, layer := range manifest[0].Layers {
		layers = append(layers, strings.TrimSuffix(layer, "/layer.tar"))
	}
	return layers, nil
}

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

func listenHTTP(path string, ch chan error) {
	fileServer := func(path string) http.Handler {
		fc := func(w http.ResponseWriter, r *http.Request) {
			http.FileServer(http.Dir(path)).ServeHTTP(w, r)
			return
		}
		return http.HandlerFunc(fc)
	}

	ch <- http.ListenAndServe(":"+strconv.Itoa(httpPort), fileServer(path))
}

func analyzeLayer(clairURL, path, layerName, parentLayerName string) error {
	payload := v1.LayerEnvelope{
		Layer: &v1.Layer{
			Name:       layerName,
			Path:       path,
			ParentName: parentLayerName,
			Format:     "Docker",
		},
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	request, err := http.NewRequest("POST", clairURL+postLayerURI, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 201 {
		body, _ := ioutil.ReadAll(response.Body)
		return fmt.Errorf("Got response %d with message %s", response.StatusCode, string(body))
	}

	return nil
}
func getVulnerabilities(clairURL string, layerIds []string) ([]vulnerabilityInfo, error) {
	var vulnerabilities = make([]vulnerabilityInfo, 0)
	//Last layer gives you all the vulnerabilities of all layers
	rawVulnerabilities, err := fetchLayerVulnerabilities(clairURL, layerIds[len(layerIds)-1])
	if err != nil {
		return vulnerabilities, err
	}
	if len(rawVulnerabilities.Features) == 0 {
		fmt.Printf("%s No features have been detected in the image. This usually means that the image isn't supported by Clair.\n", color.YellowString("NOTE:"))
		return vulnerabilities, nil
	}

	for _, feature := range rawVulnerabilities.Features {
		if len(feature.Vulnerabilities) > 0 {
			for _, vulnerability := range feature.Vulnerabilities {
				vulnerability := vulnerabilityInfo{vulnerability.Name, vulnerability.NamespaceName, vulnerability.Severity}
				vulnerabilities = append(vulnerabilities, vulnerability)
			}
		}
	}
	return vulnerabilities, nil
}

func fetchLayerVulnerabilities(clairURL string, layerID string) (v1.Layer, error) {
	response, err := http.Get(clairURL + fmt.Sprintf(getLayerFeaturesURI, layerID))
	if err != nil {
		return v1.Layer{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		body, _ := ioutil.ReadAll(response.Body)
		err := fmt.Errorf("Got response %d with message %s", response.StatusCode, string(body))
		return v1.Layer{}, err
	}

	var apiResponse v1.LayerEnvelope
	if err = json.NewDecoder(response.Body).Decode(&apiResponse); err != nil {
		return v1.Layer{}, err
	} else if apiResponse.Error != nil {
		return v1.Layer{}, errors.New(apiResponse.Error.Message)
	}

	return *apiResponse.Layer, nil
}
