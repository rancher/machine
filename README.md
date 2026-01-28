# Rancher Machine, a fork of [Docker Machine](https://github.com/docker/machine)

Machine lets you create Docker hosts on your computer, on cloud providers, and
inside your own data center. It creates servers, installs Docker on them, then
configures the Docker client to talk to them.

## Installation and documentation
The original full Docker Machine documentation [is available here](https://gcbw.github.io/docker.github.io/machine/).

This project is intended to be embedded and executed by the full [Rancher](https://github.com/rancher/rancher) product
and the stand alone cli functionality will remain but the human use of it will not be the primary focus as we will expect
inputs provided by other things like Terraform or UIs.

Cli binaries can be found in our [Releases Pages](https://github.com/rancher/machine/releases)

## Issues

For historical context you can read the [Docker Machine Issues](https://github.com/docker/machine/issues)
but all new issues created for Rancher Machine will need to be created 
in [Rancher](https://github.com/rancher/rancher/issues) 

## Driver Plugins

In addition to the core driver plugins bundled alongside Rancher Machine, users
can make and distribute their own plugin for any virtualization technology or
cloud provider.  To browse the list of known Rancher Machine plugins, please [see
this document in our
docs repo](https://github.com/docker/docker.github.io/blob/master/machine/AVAILABLE_DRIVER_PLUGINS.md).

## Releasing a New Version

- **Prerequisite:**

	- Ensure all release changes are already merged into the `master` branch before creating a tag. This process creates the tag from the latest `master` commit.

- **Prepare `master` and remote:**

	- Choose your release remote (replace `<remote>`):

		- `git fetch <remote> --tags`
		- `git checkout master`
		- `git pull --ff-only <remote> master`

- **Verify the latest tag (locally):**

	- `git describe --tags --abbrev=0`

- **Create tag (from latest `master`):**

	- `git tag v0.15.0-rancher<NEW-VERSION>`

- **Push the tag to your remote:**

	- Push single tag: `git push <remote> v0.15.0-rancher<NEW-VERSION>`

- **Verify the tag is on the remote:**

	- `git ls-remote --tags <remote> | grep v0.15.0-rancher<NEW-VERSION>`
