FROM ghcr.io/openbios/fcode-utils:master AS cross

RUN apt-get update && \
    apt-get install -y wget xz-utils tar && \
    wget https://mirrors.edge.kernel.org/pub/tools/crosstool/files/bin/x86_64/10.1.0/x86_64-gcc-10.1.0-nolibc-sparc64-linux.tar.xz && \
    tar Jxf x86_64-gcc-10.1.0-nolibc-sparc64-linux.tar.xz && \
    rm -f x86_64-gcc-10.1.0-nolibc-sparc64-linux.tar.xz && \
    wget https://mirrors.edge.kernel.org/pub/tools/crosstool/files/bin/x86_64/10.1.0/x86_64-gcc-10.1.0-nolibc-powerpc-linux.tar.xz && \
    tar Jxf x86_64-gcc-10.1.0-nolibc-powerpc-linux.tar.xz && \
    rm -f x86_64-gcc-10.1.0-nolibc-powerpc-linux.tar.xz

FROM ghcr.io/openbios/fcode-utils:master AS builder

COPY --from=cross /gcc-10.1.0-nolibc /gcc-10.1.0-nolibc

RUN apt-get update && \
    apt-get install -y make xsltproc gcc gcc-multilib zip

ENV PATH /gcc-10.1.0-nolibc/sparc64-linux/bin:/gcc-10.1.0-nolibc/powerpc-linux/bin:$PATH
