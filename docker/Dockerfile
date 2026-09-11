FROM ubuntu:24.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG BUILD_JOBS=8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        git \
        libaio-dev \
        libdw-dev \
        libfdt-dev \
        libglib2.0-dev \
        libnuma-dev \
        libpixman-1-dev \
        libslirp-dev \
        ninja-build \
        pkg-config \
        python3 \
        python3-venv \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src/femu
COPY . .

# FEMU carries a compatible Meson wheel in python/wheels. QEMU may still fetch
# pinned source subprojects that are not populated in the source checkout.
RUN mkdir -p build-docker \
    && cd build-docker \
    && ../configure \
        --enable-kvm \
        --enable-slirp \
        --target-list=x86_64-softmmu \
        --disable-docs \
        --disable-gtk \
        --disable-sdl \
        --disable-werror \
        --enable-strip \
        --prefix=/opt/femu \
    && ninja -j "${BUILD_JOBS}" \
    && ninja install \
    && /opt/femu/bin/qemu-system-x86_64 --version

FROM ubuntu:24.04 AS runtime

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        libaio1t64 \
        libdw1t64 \
        libfdt1 \
        libglib2.0-0t64 \
        libnuma1 \
        libpixman-1-0 \
        libslirp0 \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/femu /opt/femu

COPY docker/femu-run /usr/local/bin/femu-run
RUN chmod 0755 /usr/local/bin/femu-run \
    && mkdir -p /images /data

ENV PATH="/opt/femu/bin:${PATH}"
ENTRYPOINT ["/usr/local/bin/femu-run"]
CMD ["help"]
