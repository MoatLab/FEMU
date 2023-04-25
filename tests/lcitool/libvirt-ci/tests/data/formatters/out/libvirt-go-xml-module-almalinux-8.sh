function install_buildenv() {
    dnf update -y
    dnf install 'dnf-command(config-manager)' -y
    dnf config-manager --set-enabled -y powertools
    dnf install -y centos-release-advanced-virtualization
    dnf install -y epel-release
    dnf install -y \
        ca-certificates \
        git \
        glibc-langpack-en \
        golang
    rpm -qa | sort > /packages.txt
}

export LANG="en_US.UTF-8"