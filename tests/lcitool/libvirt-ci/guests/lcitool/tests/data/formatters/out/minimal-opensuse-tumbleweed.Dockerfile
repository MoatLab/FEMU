FROM registry.opensuse.org/opensuse/tumbleweed:latest

RUN zypper dist-upgrade -y && \
    zypper install -y \
           ca-certificates \
           gcc \
           git \
           glib2-devel \
           glibc-locale \
           gtk-doc \
           pkgconfig && \
    zypper clean --all && \
    rpm -qa | sort > /packages.txt

ENV LANG "en_US.UTF-8"