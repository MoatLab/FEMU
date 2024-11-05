function install_buildenv() {
    apk update
    apk upgrade
    apk add \
        ca-certificates \
        git \
        go
    apk list | sort > /packages.txt
}

export LANG="en_US.UTF-8"