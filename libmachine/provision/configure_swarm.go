package provision

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/rancher/machine/libmachine/auth"
	"github.com/rancher/machine/libmachine/engine"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcndockerclient"
	"github.com/rancher/machine/libmachine/swarm"
)

func configureSwarm(p Provisioner, swarmOptions swarm.Options, authOptions auth.Options) error {
	if !swarmOptions.IsSwarm {
		return nil
	}

	log.Info("Configuring swarm...")

	ip, err := p.GetDriver().GetIP()
	if err != nil {
		return err
	}

	u, err := url.Parse(swarmOptions.Host)
	if err != nil {
		return err
	}

	enginePort := engine.DefaultPort
	engineURL, err := p.GetDriver().GetURL()
	if err != nil {
		return err
	}

	parts := strings.Split(engineURL, ":")
	if len(parts) == 3 {
		dPort, err := strconv.Atoi(parts[2])
		if err != nil {
			return err
		}
		enginePort = dPort
	}

	parts = strings.Split(u.Host, ":")
	port := parts[1]

	dockerDir := p.GetDockerOptionsDir()
	dockerHost := &mcndockerclient.RemoteDocker{
		HostURL:    fmt.Sprintf("tcp://%s:%d", ip, enginePort),
		AuthOption: &authOptions,
	}
	advertiseInfo := fmt.Sprintf("%s:%d", ip, enginePort)

	if swarmOptions.Master {
		advertiseMasterInfo := fmt.Sprintf("%s:%s", ip, "3376")
		cmd := fmt.Sprintf("manage --tlsverify --tlscacert=%s --tlscert=%s --tlskey=%s -H %s --strategy %s --advertise %s",
			authOptions.CaCertRemotePath,
			authOptions.ServerCertRemotePath,
			authOptions.ServerKeyRemotePath,
			swarmOptions.Host,
			swarmOptions.Strategy,
			advertiseMasterInfo,
		)
		if swarmOptions.IsExperimental {
			cmd = "--experimental " + cmd
		}

		cmdMaster := strings.Fields(cmd)
		for _, option := range swarmOptions.ArbitraryFlags {
			cmdMaster = append(cmdMaster, "--"+option)
		}
		cmdMaster = append(cmdMaster, swarmOptions.Discovery)

		hostBind := fmt.Sprintf("%s:%s", dockerDir, dockerDir)
		portBinding := nat.Port(fmt.Sprintf("%s/tcp", port))
		masterHostConfig := &container.HostConfig{
			RestartPolicy: container.RestartPolicy{Name: "always", MaximumRetryCount: 0},
			Binds:         []string{hostBind},
			PortBindings: nat.PortMap{
				portBinding: {{HostIP: "0.0.0.0", HostPort: port}},
			},
		}

		exposedPorts := nat.PortSet{"2375/tcp": {}, portBinding: {}}
		swarmMasterConfig := &container.Config{
			Image:        swarmOptions.Image,
			Env:          swarmOptions.Env,
			ExposedPorts: exposedPorts,
			Cmd:          cmdMaster,
		}

		err = mcndockerclient.CreateContainer(dockerHost, swarmMasterConfig, masterHostConfig, "swarm-agent-master")
		if err != nil {
			return err
		}
	}

	if swarmOptions.Agent {
		workerHostConfig := &container.HostConfig{
			RestartPolicy: container.RestartPolicy{Name: "always", MaximumRetryCount: 0},
		}

		cmdWorker := []string{"join", "--advertise", advertiseInfo}
		for _, option := range swarmOptions.ArbitraryJoinFlags {
			cmdWorker = append(cmdWorker, "--"+option)
		}
		cmdWorker = append(cmdWorker, swarmOptions.Discovery)
		if swarmOptions.IsExperimental {
			cmdWorker = append([]string{"--experimental"}, cmdWorker...)
		}

		swarmWorkerConfig := &container.Config{
			Image: swarmOptions.Image,
			Env:   swarmOptions.Env,
			Cmd:   cmdWorker,
		}

		err = mcndockerclient.CreateContainer(dockerHost, swarmWorkerConfig, workerHostConfig, "swarm-agent")
		if err != nil {
			return err
		}
	}
	return nil
}
