FROM docker.io/library/alpine:3

RUN apk update && \
    apk upgrade && \
    apk add clang git && \
    apk list --installed | sort > /packages.txt

COPY clang-format.sh /clang-format
