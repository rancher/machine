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

## Branching and Versioning

* `master` is the primary development branch and always contains the latest changes.
* Stable tags from `master` are consumed by Rancher's `main` branch.
* Each Rancher release line has a corresponding `release/vX.Y` branch, created from `master`.
* Release branches only receive bug fixes and security patches.
* Release branch tags increment only the patch suffix (`.x`). 
  * For example, in the `release/v2.14` branch: `v0.15.0-rancher142.2`, `v0.15.0-rancher142.3`, `v0.15.0-rancher142.4`
* Release candidates (RCs) may also be created from release branches before a stable release.
* Release candidates (RCs) tag format is `vX.Y.Z-rancherN-rc.M` where `M` is incremented for each new RC.

| Machine Branch  | Rancher Release Line | Tag Format             |
|-----------------|----------------------|------------------------|
| `master`        | `main`               | `vX.Y.Z-rancherN`      |
| `release/v2.15` | `v2.15`              | `v0.15.0-rancher145.x` |
| `release/v2.14` | `v2.14`              | `v0.15.0-rancher142.x` |
| `release/v2.13` | `v2.13`              | `v0.15.0-rancher137.x` |
| `release/v2.12` | `v2.12`              | `v0.15.0-rancher133.x` |

### Automated `master` Release Candidates

The `Daily Master Tag` workflow runs daily to create RC tags for `master`.

* If `master` has changed since the latest `vX.Y.Z-rancherN` or `vX.Y.Z-rancherN-rc.M` tag, it creates the next RC tag.
* Otherwise, no tag is created.
* After a stable release (`vX.Y.Z-rancherN`), RCs start at `vX.Y.Z-rancher(N+1)-rc.0` and increment with each new commit.
* Stable releases are still created manually.
* Release branch tags (`.x`) are ignored by this workflow.

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
