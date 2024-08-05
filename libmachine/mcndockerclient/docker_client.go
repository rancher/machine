package mcndockerclient

import (
	"fmt"

	docker "github.com/fsouza/go-dockerclient"
)

// DockerClient creates a docker client for a given host.
func DockerClient(dockerHost DockerHost) (*docker.Client, error) {
	url, err := dockerHost.URL()
	if err != nil {
		return nil, err
	}

	auth := dockerHost.AuthOptions()
	return docker.NewTLSClient(url, auth.ClientCertPath, auth.ClientKeyPath, auth.CaCertPath)
}

// CreateContainer creates a docker container.
func CreateContainer(dockerHost DockerHost, config *docker.Config, hostConfig *docker.HostConfig, name string) error {
	client, err := DockerClient(dockerHost)
	if err != nil {
		return err
	}

	// Pull the image
	if err := client.PullImage(docker.PullImageOptions{Repository: config.Image}, docker.AuthConfiguration{}); err != nil {
		return fmt.Errorf("Unable to pull image: %s", err)
	}

	// Create the container
	container, err := client.CreateContainer(docker.CreateContainerOptions{
		Name:       name,
		Config:     config,
		HostConfig: hostConfig,
	})
	if err != nil {
		return fmt.Errorf("Error while creating container: %s", err)
	}

	// Start the container
	if err := client.StartContainer(container.ID, hostConfig); err != nil {
		return fmt.Errorf("Error while starting container: %s", err)
	}

	return nil
}
