FROM fedora-rawhide-common

RUN nosync dnf install -y \
               mingw64-gcc \
               mingw64-headers \
               mingw64-pkg-config && \
    nosync dnf clean all -y && \
    rpm -qa | sort > /packages.txt && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/x86_64-w64-mingw32-cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/x86_64-w64-mingw32-gcc

ENV ABI "x86_64-w64-mingw32"