# Build FEMU

How to get the source, install dependencies and build the FEMU binary. Check
[requirements.md](requirements.md) first.

## Clone

```bash
git clone https://github.com/MoatLab/FEMU.git
cd FEMU
```

The repository has no git submodules. QEMU's build downloads a few meson
subprojects (for example `keycodemapdb` and `berkeley-softfloat-3`) during
`configure`, so the first build needs network access.

## Dependencies

On Debian and Ubuntu, `pkgdep.sh` installs what the build needs. It must run as
root:

```bash
mkdir build-femu
cd build-femu
cp ../femu-scripts/femu-copy-scripts.sh .
./femu-copy-scripts.sh
sudo ./pkgdep.sh
```

`femu-scripts` is a link to `hw/femu/scripts`. `femu-copy-scripts.sh` copies the
build helpers, the image builder and the run scripts into `build-femu/`.

`pkgdep.sh` installs `gcc pkg-config git libglib2.0-dev libfdt-dev
libpixman-1-dev zlib1g-dev libdw-dev libaio-dev libslirp-dev libnuma-dev
ninja-build`. QEMU's `configure` also needs `python3-venv`, `flex` and `bison`;
install them if `configure` asks:

```bash
sudo apt install python3-venv flex bison
```

CI installs a longer list, which is a known-good superset
(`.github/workflows/ci.yml`, step "Install dependencies"):

```bash
sudo apt install -y build-essential pkg-config libglib2.0-dev \
  libpixman-1-dev libfdt-dev zlib1g-dev libaio-dev \
  libcap-ng-dev libattr1-dev ninja-build python3-pip \
  libslirp-dev libseccomp-dev libcurl4-gnutls-dev \
  libiscsi-dev libnfs-dev librbd-dev librados-dev \
  libssh-dev liblzo2-dev libsnappy-dev libbz2-dev \
  liblzma-dev libzstd-dev libgcrypt20-dev libgnutls28-dev \
  uuid-dev libcap-dev libxml2-dev libmount-dev \
  liburing-dev flex bison
```

## Compile

From `build-femu/`:

```bash
./femu-compile.sh
```

The script runs `make clean`, then

```bash
../configure --enable-kvm --target-list=x86_64-softmmu --enable-slirp \
    --disable-libnfs --disable-libiscsi --disable-curl
```

and `make` with one job per CPU. A first build takes 3 to 15 minutes,
depending on the number of cores.

The binary is `build-femu/qemu-system-x86_64`. The run scripts expect it in the
current directory, so run them from `build-femu/`. The build also produces
`build-femu/qemu-img`, which `make-guest-image.sh` uses.

Check that the FEMU devices are registered:

```bash
./qemu-system-x86_64 -device help | grep femu
```

You should see the NVMe controller, the CXL SSD and the NVMe subsystem:

```
name "femu", bus PCI, desc "FEMU Non-Volatile Memory Express"
name "femu-cxl-ssd", bus PCI, desc "FEMU CXL SSD"
name "femu-subsys", desc "FEMU NVMe Subsystem (FDP)"
```

`./qemu-system-x86_64 -device femu,help` lists every property with its
default; [the property reference](../reference/properties.md) explains them.

## Optional features

### CSD with uBPF programs

Computational storage mode (`femu_mode=4`) loads shared-library programs with no
extra build option. To also run uBPF programs, build with uBPF:

```bash
./femu-compile.sh --enable-csd-ubpf                     # libubpf found by pkg-config
./femu-compile.sh --enable-csd-ubpf=/path/to/ubpf-cemu  # a ubpf-cemu source tree
```

With a path, the build links `<path>/build/lib/libubpf.a`. These are the only
options `femu-compile.sh` accepts.

### CXL SSD

`femu-cxl-ssd` is built by default for `x86_64-softmmu`. It needs no option.
Check it with:

```bash
./qemu-system-x86_64 -device help | grep femu-cxl-ssd
```

### Debug build

`femu-compile.sh` has no debug switch. Run `configure` yourself from
`build-femu/`:

```bash
../configure --enable-kvm --target-list=x86_64-softmmu --enable-slirp \
    --disable-libnfs --disable-libiscsi --disable-curl \
    --enable-debug --enable-debug-info
make -j"$(nproc)"
```

Add `--extra-cflags=-DFEMU_FTL_ASSERT` to turn on the FTL consistency checks
that are compiled out by default.

## Rebuild

After you change the source, rerun `make` from `build-femu/`. It rebuilds only
what changed:

```bash
make -j"$(nproc)"
```

`./femu-compile.sh` always starts with `make clean` and reruns `configure`, so
use it only for a full rebuild.

After you pull new scripts, run `./femu-copy-scripts.sh` again. It overwrites
the copies in `build-femu/`, including any run script you edited there.

## Common build errors

| Message | Cause | Fix |
| --- | --- | --- |
| `ERROR: Cannot find Ninja` | `ninja-build` is missing | `sudo apt install ninja-build` |
| `ERROR: python venv creation failed` | Debian and Ubuntu ship `venv` in a separate package | `sudo apt install python3-venv` |
| `ERROR: Cannot use 'python3', Python >= 3.9 is required.` | Python is older than 3.9 (Ubuntu 20.04) | Use Ubuntu 22.04 or newer |
| `Dependency "glib-2.0" not found` or a version below 2.66 | GLib is missing or too old | `sudo apt install libglib2.0-dev`; on Ubuntu 20.04, upgrade the distribution |
| Errors around `nfs_pread_async` | The libnfs 6 API changed | `femu-compile.sh` passes `--disable-libnfs`. Use it, or pass the flag yourself. |
| A meson subproject fails to download | No network during `configure` | Build once with network access |
| `pkgdep: unsupported system type` | Not Debian or Ubuntu | Install the equivalent packages by hand |
| A warning stops the build (`-Werror`) | A newer compiler warns where QEMU 10.1's did not | Add `--disable-werror` to the `configure` line, and please report the warning |
