SCRIPT_TARGETS := ci clean package release test validate
ARCH ?= amd64
export ARCH
PLATFORM ?= linux/$(ARCH)

BUILDX_BUILDER := machine
IMAGE_BUILDER ?= docker buildx
DEFAULT_PLATFORMS := linux/amd64,linux/arm64
BUILDX_ARGS ?= --sbom=true --attest type=provenance,mode=max

$(SCRIPT_TARGETS):
	./scripts/$@

.PHONY: buildx
buildx:
	@bash -c 'set -euo pipefail; \
	source ./scripts/version; \
	BUILDX_PLATFORM="$${BUILDX_PLATFORM:-$${TARGET_PLATFORMS:-$(PLATFORM)}}"; \
	$(IMAGE_BUILDER) build \
		$${IID_FILE_FLAG:-} \
		--file package/Dockerfile \
		$${BUILDX_BUILDER_FLAG:+--builder $${BUILDX_BUILDER_FLAG}} \
		--build-arg VERSION="$${VERSION}" \
		--build-arg COMMIT="$${COMMIT}" \
		$${BUILDX_TARGET:+--target $${BUILDX_TARGET}} \
		$${BUILDX_PLATFORM:+--platform $${BUILDX_PLATFORM}} \
		$${BUILDX_OUTPUT:+--output $${BUILDX_OUTPUT}} \
		$${BUILDX_TAG_ARGS:-} \
		$${BUILDX_EXTRA_ARGS:-} \
		$${BUILDX_PUSH:+--push} \
		.'

.PHONY: build
build:
ifeq ($(CROSS),1)
	@./scripts/build
else
	@mkdir -p bin
	@$(MAKE) --no-print-directory buildx \
		BUILDX_TARGET=machine-binary \
		BUILDX_PLATFORM="$(PLATFORM)" \
		BUILDX_OUTPUT="type=local,dest=./bin"
	@chmod +x ./bin/rancher-machine
	@# Ignore exec format errors when ARCH differs from the host.
	@./bin/rancher-machine --version || true
endif

.PHONY: buildx-builder
buildx-builder:
	@docker buildx inspect $(BUILDX_BUILDER) >/dev/null 2>&1 || docker buildx create --name=$(BUILDX_BUILDER) --platform=$(DEFAULT_PLATFORMS)

.PHONY: push-image
push-image: buildx-builder
	@echo "--- Building and Pushing Image ---"
	@bash -c 'set -euo pipefail; \
	source ./scripts/version; \
	IMAGE="$${REPO}/machine:$${TAG}"; \
	$(MAKE) --no-print-directory buildx \
		BUILDX_BUILDER_FLAG="$(BUILDX_BUILDER)" \
		BUILDX_TAG_ARGS="--tag $${IMAGE}" \
		BUILDX_EXTRA_ARGS="$(BUILDX_ARGS)" \
		BUILDX_PUSH=1 \
		IID_FILE_FLAG="$${IID_FILE_FLAG:-}"; \
	echo "Pushed $${IMAGE}"'

.DEFAULT_GOAL := ci

.PHONY: $(SCRIPT_TARGETS)
