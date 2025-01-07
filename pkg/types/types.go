package types

// DockerData represents the structure of the manifest data
type DockerData struct {
	Manifests []struct {
		Digest string `json:"digest"`
	} `json:"manifests"`
}

// ManifestData represents the structure of a manifest file
type ManifestData struct {
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

// LayerURI contains information about a layer
type LayerURI struct {
	Hash string `json:"hash"`
	URI  string `json:"uri"`
}

// Payload is used to prepare data for Clair Indexer
type Payload struct {
	Hash   string     `json:"hash"`
	Layers []LayerURI `json:"layers"`
}

// TODO Add support for older version of docker

type manifestJSON struct {
	Layers []string `json:"layers"`
}
