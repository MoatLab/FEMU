FROM registry.opensuse.org/opensuse/leap:15.6

RUN zypper update -y && \
    zypper addrepo -fc https://download.opensuse.org/update/leap/15.6/backports/openSUSE:Backports:SLE-15-SP6:Update.repo && \
    zypper install -y \
           ca-certificates \
           git \
           glibc-locale \
           go && \
    zypper clean --all && \
    rpm -qa | sort > /packages.txt

ENV LANG "en_US.UTF-8"