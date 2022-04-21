FROM registry.fedoraproject.org/fedora:rawhide

RUN dnf update -y --nogpgcheck fedora-gpg-keys && \
    dnf install -y nosync && \
    echo -e '#!/bin/sh\n\
if test -d /usr/lib64\n\
then\n\
    export LD_PRELOAD=/usr/lib64/nosync/nosync.so\n\
else\n\
    export LD_PRELOAD=/usr/lib/nosync/nosync.so\n\
fi\n\
exec "$@"' > /usr/bin/nosync && \
    chmod +x /usr/bin/nosync && \
    nosync dnf distro-sync -y && \
    nosync dnf install -y \
        ca-certificates \
        git \
        glibc-langpack-en \
        gtk-doc && \
    nosync dnf autoremove -y && \
    nosync dnf clean all -y

ENV LANG "en_US.UTF-8"

RUN nosync dnf install -y \
        mingw64-gcc \
        mingw64-glib2 \
        mingw64-pkg-config && \
    nosync dnf clean all -y && \
    rpm -qa | sort > /packages.txt

ENV ABI "x86_64-w64-mingw32"