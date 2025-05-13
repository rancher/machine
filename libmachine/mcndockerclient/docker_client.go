package mcndockerclient

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/rancher/machine/libmachine/cert"
)

// DockerClient creates a docker client for a given host.
func DockerClient(dockerHost DockerHost) (*client.Client, error) {
	url, err := dockerHost.URL()
	if err != nil {
		return nil, err
	}

	tlsConfig, err := cert.ReadTLSConfig(url, dockerHost.AuthOptions())
	if err != nil {
		return nil, fmt.Errorf("unable to read TLS config: %s", err)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}

	return client.NewClientWithOpts(
		client.WithHost(url),
		client.WithHTTPClient(httpClient),
		client.WithAPIVersionNegotiation(),
	)
}

// CreateContainer creates a docker container.
func CreateContainer(dockerHost DockerHost, config *container.Config, hostConfig *container.HostConfig, name string) error {
	cli, err := DockerClient(dockerHost)
	if err != nil {
		return err
	}
	ctx := context.Background()

	_, err = cli.ImagePull(ctx, config.Image, types.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("unable to pull image: %s", err)
	}

	resp, err := cli.ContainerCreate(ctx, config, hostConfig, nil, nil, name)
	if err != nil {
		return fmt.Errorf("error while creating container: %s", err)
	}

	if err = cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("error while starting container: %s", err)
	}

	return nil
}
