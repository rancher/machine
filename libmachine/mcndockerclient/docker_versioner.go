package mcndockerclient

import (
	"context"
	"fmt"
)

var CurrentDockerVersioner DockerVersioner = &defaultDockerVersioner{}

type DockerVersioner interface {
	DockerVersion(host DockerHost) (string, error)
}

func DockerVersion(host DockerHost) (string, error) {
	return CurrentDockerVersioner.DockerVersion(host)
}

type defaultDockerVersioner struct{}

func (dv *defaultDockerVersioner) DockerVersion(host DockerHost) (string, error) {
	client, err := DockerClient(host)
	if err != nil {
		return "", fmt.Errorf("Unable to query docker version: %s", err)
	}

	versionInfo, err := client.ServerVersion(context.Background())
	if err != nil {
		return "", fmt.Errorf("Unable to query docker version: %s", err)
	}

	return versionInfo.Version, nil
}
