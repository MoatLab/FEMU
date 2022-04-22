#!/bin/bash

set -e

source /ci/common.sh

export DEBIAN_FRONTEND=noninteractive
export LANG='C.UTF-8'
export DC=gdc

pkgs=(
  python3-pip libxml2-dev libxslt1-dev libyaml-dev libjson-glib-dev
  wget unzip cmake doxygen
  clang
  pkg-config-arm-linux-gnueabihf
  qt4-linguist-tools qt5-default qtbase5-private-dev
  python-dev
  libomp-dev
  llvm lcov
  ldc
  libclang-dev
  libgcrypt20-dev
  libgpgme-dev
  libhdf5-dev openssh-server
  libboost-python-dev libboost-regex-dev
  libblocksruntime-dev
  libperl-dev libscalapack-mpi-dev libncurses-dev
)

boost_pkgs=(atomic chrono date-time filesystem log regex serialization system test thread)

sed -i '/^#\sdeb-src /s/^#//' "/etc/apt/sources.list"
apt-get -y update
apt-get -y upgrade
apt-get -y install eatmydata

# Base stuff
eatmydata apt-get -y build-dep meson

# Add boost packages
for i in "${boost_pkgs[@]}"; do
  for j in "1.62.0" "1.65.1"; do
    pkgs+=("libboost-${i}${j}")
  done
done

# packages
eatmydata apt-get -y install "${pkgs[@]}"

install_python_packages

# Install the ninja 0.10
wget https://github.com/ninja-build/ninja/releases/download/v1.10.0/ninja-linux.zip
unzip ninja-linux.zip -d /ci

# cleanup
apt-get -y remove ninja-build
apt-get -y clean
apt-get -y autoclean
rm ninja-linux.zip
