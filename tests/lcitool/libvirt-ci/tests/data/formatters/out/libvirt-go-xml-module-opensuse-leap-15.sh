function install_buildenv() {
    zypper update -y
    zypper addrepo -fc https://download.opensuse.org/update/leap/15.6/backports/openSUSE:Backports:SLE-15-SP6:Update.repo
    zypper install -y \
           ca-certificates \
           git \
           glibc-locale \
           go
    rpm -qa | sort > /packages.txt
}

export LANG="en_US.UTF-8"