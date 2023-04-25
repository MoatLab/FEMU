FROM docker.io/library/almalinux:9

RUN dnf update -y && \
    dnf install 'dnf-command(config-manager)' -y && \
    dnf config-manager --set-enabled -y crb && \
    dnf install -y epel-release && \
    dnf install -y \
        SDL2-devel \
        alsa-lib-devel \
        ant \
        ant-junit \
        audit-libs-devel \
        augeas \
        autoconf \
        automake \
        bash \
        bash-completion \
        bc \
        bison \
        brlapi-devel \
        bzip2 \
        bzip2-devel \
        ca-certificates \
        cargo \
        ccache \
        check-devel \
        clang \
        clang-devel \
        clippy \
        cpp \
        cyrus-sasl-devel \
        daxctl-devel \
        dbus-daemon \
        device-mapper-devel \
        device-mapper-multipath-devel \
        diffutils \
        dwarves \
        e2fsprogs \
        ebtables \
        expect \
        findutils \
        firewalld-filesystem \
        flex \
        fuse-devel \
        fuse3 \
        fuse3-devel \
        gcc \
        gcc-c++ \
        gdk-pixbuf2-devel \
        gettext \
        gettext-devel \
        git \
        glib2-devel \
        glib2-static \
        glibc-devel \
        glibc-langpack-en \
        glibc-static \
        gnutls-devel \
        gnutls-utils \
        gobject-introspection-devel \
        golang \
        grep \
        gtk-doc \
        gtk-update-icon-cache \
        gtk3-devel \
        guestfs-tools \
        gzip \
        hostname \
        https://kojipkgs.fedoraproject.org/packages/capstone/4.0.2/9.el9/x86_64/capstone-4.0.2-9.el9.x86_64.rpm \
        hwdata \
        icoutils \
        iproute \
        iproute-tc \
        iptables \
        iscsi-initiator-utils \
        java-11-openjdk-headless \
        jemalloc-devel \
        jna \
        jq \
        json-c-devel \
        json-glib-devel \
        junit \
        kmod \
        libacl-devel \
        libaio-devel \
        libarchive-devel \
        libasan \
        libattr-devel \
        libblkid-devel \
        libbpf-devel \
        libcap-ng-devel \
        libcmocka-devel \
        libconfig-devel \
        libcurl-devel \
        libdrm-devel \
        libepoxy-devel \
        libfdt-devel \
        libffi-devel \
        libgcrypt-devel \
        libguestfs-devel \
        libjpeg-devel \
        libnbd-devel \
        libnl3-devel \
        libpcap-devel \
        libpciaccess-devel \
        libpmem-devel \
        libpng-devel \
        librbd-devel \
        libseccomp-devel \
        libselinux-devel \
        libsoup-devel \
        libssh-devel \
        libssh2-devel \
        libtasn1-devel \
        libtirpc-devel \
        libtool \
        libtorrent-devel \
        libubsan \
        libusbx-devel \
        libuuid-devel \
        libvirt-devel \
        libwsman-devel \
        libxml2 \
        libxml2-devel \
        libxslt \
        libxslt-devel \
        libzstd-devel \
        llvm \
        lttng-ust-devel \
        lua-devel \
        lvm2 \
        lzo-devel \
        make \
        mesa-libgbm-devel \
        meson \
        nbdkit \
        ncurses-devel \
        net-snmp-devel \
        nettle-devel \
        nfs-utils \
        ninja-build \
        nmap-ncat \
        numactl-devel \
        numad \
        ocaml \
        ocaml-findlib \
        ocamldoc \
        openssh-clients \
        osinfo-db-tools \
        pam-devel \
        parted-devel \
        pcre-static \
        perl-App-cpanminus \
        perl-Archive-Tar \
        perl-CPAN-Changes \
        perl-Digest \
        perl-Digest-MD5 \
        perl-ExtUtils-CBuilder \
        perl-ExtUtils-Embed \
        perl-File-Slurp \
        perl-IO-Compress-Bzip2 \
        perl-IO-Interface \
        perl-IO-String \
        perl-Module-Build \
        perl-Net-SNMP \
        perl-NetAddr-IP \
        perl-Pod-Simple \
        perl-Sub-Uplevel \
        perl-Sys-Hostname \
        perl-Test-Exception \
        perl-Test-Pod \
        perl-Test-Pod-Coverage \
        perl-Test-Simple \
        perl-Time-HiRes \
        perl-XML-Twig \
        perl-XML-Writer \
        perl-XML-XPath \
        perl-YAML \
        perl-base \
        perl-devel \
        perl-generators \
        perl-podlators \
        php-devel \
        pixman-devel \
        pkgconfig \
        polkit \
        pulseaudio-libs-devel \
        python3 \
        python3-PyYAML \
        python3-boto3 \
        python3-dbus \
        python3-devel \
        python3-docutils \
        python3-gobject \
        python3-libnbd \
        python3-libxml2 \
        python3-lxml \
        python3-numpy \
        python3-pip \
        python3-pytest \
        python3-requests \
        python3-setuptools \
        python3-sphinx \
        python3-sphinx_rtd_theme \
        python3-wheel \
        qemu-img \
        qemu-kvm \
        rdma-core-devel \
        readline-devel \
        rpcgen \
        rpm \
        rpm-build \
        ruby-devel \
        rubygem-rake \
        rust \
        sanlock-devel \
        scrub \
        sed \
        snappy-devel \
        socat \
        spice-protocol \
        systemd-devel \
        systemd-rpm-macros \
        systemtap-sdt-devel \
        tar \
        tcl-devel \
        tcpdump \
        texinfo \
        unzip \
        usbredir-devel \
        util-linux \
        vala \
        valgrind \
        vte291-devel \
        wget \
        which \
        wireshark-devel \
        xfsprogs-devel \
        xorriso \
        xz \
        xz-devel \
        yajl-devel \
        zip \
        zlib-devel \
        zlib-static && \
    dnf autoremove -y && \
    dnf clean all -y && \
    rpm -qa | sort > /packages.txt && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/c++ && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/clang && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/g++ && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/gcc

RUN /usr/bin/pip3 install \
                  flake8 \
                  pillow

RUN cpanm --notest \
          LWP::UserAgent \
          Net::OpenSSH \
          TAP::Formatter::HTML \
          TAP::Formatter::JUnit \
          TAP::Harness::Archive \
          accessors

ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"
ENV LANG "en_US.UTF-8"
ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"