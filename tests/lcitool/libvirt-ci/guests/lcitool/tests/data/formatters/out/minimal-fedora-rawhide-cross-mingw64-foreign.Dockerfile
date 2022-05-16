FROM registry.fedoraproject.org/fedora:rawhide

RUN nosync dnf install -y \
        mingw64-gcc \
        mingw64-glib2 \
        mingw64-pkg-config && \
    nosync dnf clean all -y && \
    rpm -qa | sort > /packages.txt

ENV ABI "x86_64-w64-mingw32"