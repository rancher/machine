FROM registry.suse.com/bci/bci-base:15.5

ENV SSL_CERT_DIR /etc/rancher/ssl

RUN zypper -n update && \
    zypper -n install git-core curl ca-certificates unzip mkisofs xz gzip sed tar openssh-clients && \
    zypper -n clean -a && \
    rm -rf /tmp/* /var/tmp/* /usr/share/doc/packages/*

RUN useradd -m -u 1000 machine

RUN mkdir -p .docker/machine/machines /etc/rancher/ssl /home/machine/bin && \
    chown -R machine /etc/rancher/ssl

COPY download_driver.sh rancher-machine entrypoint.sh /home/machine/bin/

RUN chmod -R 700 /home/machine/bin && \
    chown -R machine /home/machine

USER 1000

ENV PATH="$PATH:/home/machine/bin"

WORKDIR /home/machine

ENTRYPOINT ["entrypoint.sh"]
