FROM registry.opensuse.org/opensuse/tumbleweed:latest

RUN zypper dist-upgrade -y && \
    zypper install -y \
           ca-certificates \
           git \
           glibc-locale \
           go && \
    zypper clean --all && \
    rpm -qa | sort > /packages.txt

ENV LANG "en_US.UTF-8"