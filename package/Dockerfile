ARG BCI_VERSION=15.6

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

COPY download_driver.sh /chroot/usr/local/bin/
RUN chmod +x /chroot/usr/local/bin/download_driver.sh

COPY rancher-machine entrypoint.sh /chroot/usr/local/bin/
RUN chmod 0755 /chroot/usr/local/bin

FROM scratch

ENV SSL_CERT_DIR /etc/rancher/ssl

COPY --from=builder /chroot /

RUN mkdir -p .docker/machine/machines /etc/rancher/ssl /home/machine && \
    chown -R machine /etc/rancher/ssl && \
    chown -R machine /home/machine

USER 1000

ENTRYPOINT ["entrypoint.sh"]
