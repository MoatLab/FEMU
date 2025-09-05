FROM ghcr.io/openbios/fcode-utils:master AS cross

RUN apt-get update && \
    apt-get install -y \
        make xsltproc zip libc6-dev-i386 gcc gcc-multilib-powerpc-linux-gnu gcc-multilib-sparc64-linux-gnu
