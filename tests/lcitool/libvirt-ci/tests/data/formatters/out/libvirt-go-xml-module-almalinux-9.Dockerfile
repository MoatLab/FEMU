FROM docker.io/library/almalinux:9

RUN dnf update -y && \
    dnf install 'dnf-command(config-manager)' -y && \
    dnf config-manager --set-enabled -y crb && \
    dnf install -y epel-release && \
    dnf install -y \
        ca-certificates \
        git \
        glibc-langpack-en \
        golang && \
    dnf autoremove -y && \
    dnf clean all -y && \
    rpm -qa | sort > /packages.txt

ENV LANG "en_US.UTF-8"