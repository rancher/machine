FROM registry.suse.com/bci/bci-base:15.4.27.14.23

ENV SSL_CERT_DIR /etc/rancher/ssl

RUN zypper -n update && \
    zypper -n install git-core curl ca-certificates unzip mkisofs xz gzip sed tar && \
    zypper -n clean -a && \
    rm -rf /tmp/* /var/tmp/* /usr/share/doc/packages/*

RUN useradd -u 1000 machine

RUN mkdir -p .docker/machine/machines /etc/rancher/ssl /home/machine && \
    chown -R machine /etc/rancher/ssl && \
    chown -R machine /home/machine

COPY download_driver.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/download_driver.sh

COPY rancher-machine entrypoint.sh /usr/local/bin/
RUN chmod 0777 /usr/local/bin

USER 1000
WORKDIR /home/machine

ENTRYPOINT ["entrypoint.sh"]
