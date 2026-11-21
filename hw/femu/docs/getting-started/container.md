# Build and run FEMU in a container

`hw/femu/container/Containerfile` builds FEMU on a pinned Ubuntu 24.04 with
pinned packages. Use it on a host where [`pkgdep.sh`](build.md#dependencies)
does not work, or to get the same build as CI. The commands below use
`podman`; `docker` takes the same arguments.

The image is built locally. FEMU publishes no image to a registry.

## What is in the image

```
 ubuntu:24.04@sha256:...           base image, pinned by digest
   |
   v
 stage "deps"   packages from the Ubuntu snapshot of UBUNTU_SNAPSHOT
   |            (the CI build list, plus git, python3-venv, sudo and others)
   |            .devcontainer/devcontainer.json stops here
   v
 stage "femu"   the source in /femu, built in /femu/build-femu
                with femu-copy-scripts.sh and femu-compile.sh
```

The `femu` stage keeps the whole build tree, so the image takes several GiB.
In return you can run the qtests and rebuild after an edit inside it.

## Build the image

Build from the root of a clean clone. Every file in the tree except `.git`
and the build directories goes into the image, so untracked files go in too.

```sh
git clone https://github.com/MoatLab/FEMU.git
cd FEMU
podman build -f hw/femu/container/Containerfile -t femu .
```

The build needs network access: it downloads packages and QEMU's meson
subprojects. It takes about as long as a [normal build](build.md#compile).

The build ARG `UBUNTU_SNAPSHOT` sets the time of the Ubuntu archive that
the packages come from. An empty value takes the current archive, for
example for security fixes:

```sh
podman build -f hw/femu/container/Containerfile --build-arg UBUNTU_SNAPSHOT= -t femu .
```

## Check the build

The image starts in `/femu/build-femu`, where the binary and the launchers
are. The FEMU qtests need no KVM and no guest:

<!-- femu-untested: needs a container tool and the built image -->
```bash
podman run --rm femu ./qemu-system-x86_64 -device help | grep femu
podman run --rm -e QTEST_QEMU_BINARY=./qemu-system-x86_64 femu \
    ./tests/qtest/qos-test -m quick \
    -p /x86_64/pc/i440FX-pcihost/pci-bus-pc/pci-bus/femu/femu-tests
```

## Run a guest with KVM

The launchers need KVM, a guest image and an SSH port. Build the guest image
on the host with [make-guest-image.sh](guest-image.md), then pass the three
things into the container:

```
 host                                       container
 /dev/kvm ------ --device /dev/kvm -------> /dev/kvm
 ~/images ------ -v ~/images:/images -----> IMGDIR=/images
 127.0.0.1:8080 <- -p 127.0.0.1:8080:8080 - guest SSH (port 22)
 memlock   ----- --ulimit memlock=-1:-1 --> QEMU locks the device memory
```

With rootless podman (the `crun` runtime is necessary for
`keep-groups`):

<!-- femu-untested: needs a KVM host, a container tool and a guest image -->
```bash
podman run --rm -it --device /dev/kvm --group-add keep-groups \
    --ulimit memlock=-1:-1 -v "$HOME/images:/images" -e IMGDIR=/images \
    -p 127.0.0.1:8080:8080 femu ./run-blackbox.sh
```

With Docker as root, leave out `--group-add keep-groups`:

<!-- femu-untested: needs a KVM host, a container tool and a guest image -->
```bash
sudo docker run --rm -it --device /dev/kvm --ulimit memlock=-1:-1 \
    -v "$HOME/images:/images" -e IMGDIR=/images \
    -p 127.0.0.1:8080:8080 femu ./run-blackbox.sh
```

`127.0.0.1` keeps the guest SSH port off the other host interfaces.

Then log in from the clone on the host. The script reads the key from
`$HOME/images` and needs no build:

<!-- femu-untested: needs a guest that runs in the container -->
```bash
./femu-scripts/run-guest-ssh.sh
```

Notes:

- The launchers run QEMU with `sudo`. The container runs as root, so `sudo`
  asks for no password. The image sets `preserve_groups` for `sudo`, so QEMU
  keeps the groups that the container got.
- Rootless podman runs the container as your user. You must be in the `kvm`
  group (see [KVM access](requirements.md#kvm-access)), and
  `--group-add keep-groups` passes that group into the container.
- QEMU needs host RAM for `devsz_mb` plus the guest RAM (see
  [Memory](requirements.md#memory)). A `--memory` limit below that kills QEMU.
- `--ulimit memlock=-1:-1` asks for no limit. Rootless podman can only give
  the hard limit of your own session (`ulimit -Hl`). When the lock fails,
  FEMU prints a warning and runs on. That run is good for function tests.
  For latency measurements, raise the host limit until the warning is gone.
- Another SSH port needs the same number in three places: add
  `-e SSH_PORT=8081 -p 127.0.0.1:8081:8081`, and run
  `SSH_PORT=8081 ./femu-scripts/run-guest-ssh.sh` on the host.
- The standard launchers need no hugepages.
- `femu-cxl-ssd` with `der=cylon` is not supported in a container. It needs a
  modified host kernel, hugetlb memory, `/proc/self/pagemap` and
  `CAP_SYS_ADMIN` (see [cxlssd.md](../cxlssd.md)).
- A container on a virtual machine has the same latency limits as nested
  virtualization (see [Operating system and CPU](requirements.md#operating-system-and-cpu)).
- The image is always x86_64, because the digest names the `linux/amd64`
  image. On another CPU it runs only under x86_64 emulation, which is slow
  and has no KVM.
- The run scripts send QEMU's output through `tee`, so the container exit
  status does not show a QEMU start failure. Read the output.

## Develop in a devcontainer

`.devcontainer/devcontainer.json` opens the repository in the `deps` stage
with VS Code or GitHub Codespaces. The source stays on the host and is
mounted into the container. The container gets no `/dev/kvm`, so it also
opens on a host without KVM.

You work as the image's `ubuntu` user. On Linux the devcontainer tools give
that user your host UID, so files that the build makes stay yours. That user
has no `sudo`; add packages in the Containerfile instead.

Build and test inside it as on a normal host:

```sh
mkdir build-femu
cd build-femu
cp ../femu-scripts/femu-copy-scripts.sh .
./femu-copy-scripts.sh
./femu-compile.sh
```

Then run the qtests as in [Testing](../guides/testing.md#device-tests-qtest).
To boot a guest in the devcontainer, add `"runArgs": ["--device=/dev/kvm"]`
to a local copy of `devcontainer.json`.

## What CI checks

| Check | Where | Fails when |
| --- | --- | --- |
| `check-container.py --self-test`, then on the tree | `ci.yml`, every push and pull request | an outside image has no digest, the image packages differ from the CI build list, `UBUNTU_SNAPSHOT` has no fixed default, `devcontainer.json` points at the wrong file or stage or passes `/dev/kvm`, or `.dockerignore` lets `.git` or a build tree in |
| hadolint, after a planted bad file | `ci.yml`, every push and pull request | hadolint passes the planted file, or reports anything on the Containerfile |
| image build, snapshot, `-device help`, FEMU qtests | `container.yml`: changes to the container files or build scripts, weekly, manual | the image does not build, apt did not use the named snapshot, a FEMU device is missing, or a listed qtest has no result or fails in the TAP output |

CI does not open the devcontainer and does not boot a guest with KVM in the
container. Those stay manual checks.
