ARG BCI_VERSION=15.7
ARG GO_VERSION=1.25

FROM --platform=$BUILDPLATFORM registry.suse.com/bci/golang:${GO_VERSION} AS machine-build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=HEAD
ENV CGO_ENABLED=0 \
    GOCACHE=/root/.cache/go/cache
WORKDIR /src

# Keep dependency layers stable unless module metadata changes.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go/cache \
    go mod download

# Copy only the source trees needed for the rancher-machine binary.
COPY cmd/ cmd/
COPY commands/ commands/
COPY drivers/ drivers/
COPY libmachine/ libmachine/
COPY version/ version/

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go/cache \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -tags netgo -installsuffix netgo \
      -ldflags "-w -s -extldflags '-static' -X github.com/rancher/machine/version.Version=${VERSION} -X github.com/rancher/machine/version.GitCommit=${COMMIT}" \
      -o /out/rancher-machine ./cmd/rancher-machine

FROM scratch AS machine-binary
COPY --from=machine-build /out/rancher-machine /rancher-machine

FROM registry.suse.com/bci/bci-base:${BCI_VERSION} AS machine-artifacts-build
ARG TARGETARCH
COPY --from=machine-build /out/rancher-machine /tmp/rancher-machine
RUN mkdir -p /dist && tar -C /tmp -czf /dist/rancher-machine-${TARGETARCH}.tar.gz rancher-machine

FROM scratch AS machine-artifacts
COPY --from=machine-artifacts-build /dist/ /

FROM registry.suse.com/bci/bci-busybox:${BCI_VERSION} AS final
FROM registry.suse.com/bci/bci-base:${BCI_VERSION} AS builder

# Creates the base dir for the target image, and hydrates it with the
# final image's contents.
RUN mkdir /chroot
COPY --from=final / /chroot/

RUN zypper --non-interactive refresh && \
    zypper --installroot /chroot -n rm busybox-less && \
    zypper --installroot /chroot -n install \
        git-core curl mkisofs openssh-clients openssl patterns-base-fips && \
    zypper -n clean -a && \
    rm -rf /chroot/tmp/* /chroot/var/tmp/* /chroot/usr/share/doc/packages/*

RUN useradd -u 1000 machine
RUN cp /etc/passwd /chroot/etc/passwd

COPY package/download_driver.sh /chroot/usr/local/bin/
RUN chmod +x /chroot/usr/local/bin/download_driver.sh

COPY --from=machine-build /out/rancher-machine /chroot/usr/local/bin/rancher-machine
COPY package/entrypoint.sh /chroot/usr/local/bin/
RUN chmod 0755 /chroot/usr/local/bin

FROM scratch

ENV SSL_CERT_DIR=/etc/rancher/ssl

COPY --from=builder /chroot /

RUN mkdir -p .docker/machine/machines /etc/rancher/ssl /home/machine && \
    chown -R machine /etc/rancher/ssl && \
    chown -R machine /home/machine && \
    chown machine /usr/local/bin

USER 1000
WORKDIR /home/machine

ENTRYPOINT ["entrypoint.sh"]
