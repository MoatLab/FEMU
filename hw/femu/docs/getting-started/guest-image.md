# Guest image

FEMU emulates an SSD inside a virtual machine, so you need a guest disk image.
The run scripts boot `~/images/u20s.qcow2` by default. The name is historical;
the image can hold any Linux release.

## Build one with make-guest-image.sh

From `build-femu/` (after [the build](build.md)):

```sh
./make-guest-image.sh
```

The script:

1. downloads a pinned serial of the Ubuntu 24.04 cloud image;
2. checks it against a pinned SHA-256 and against Ubuntu's SHA256 sums;
3. boots it once without a display, creates user `femu` with passwordless
   `sudo`, and installs `nvme-cli`, `fio` and your kernel;
4. turns on the serial console and powers the guest off;
5. boots it again, with the disk on virtio-scsi as the run scripts attach it;
6. in that boot, checks the kernel, the tools and a writable root file system;
7. writes a standalone qcow2 (no backing file), its SHA-256 and a manifest.

It also checks the GPG signature of the sums when `gpgv` and the Ubuntu
cloud-image keyring are installed.

It writes these files to `~/images/`:

| File | Purpose |
| --- | --- |
| `u20s.qcow2` | The guest disk the run scripts boot |
| `u20s.qcow2.sha256` | Its SHA-256, in `sha256sum -c` format |
| `u20s.qcow2.manifest` | The base serial and digest, the kernel release, tool versions and build options |
| `femu-guest-key`, `femu-guest-key.pub` | SSH key for user `femu` |
| `cache/` | The downloaded cloud image and kernel packages, reused on the next run |
| `provision.log`, `check.log` | Serial logs of the two boots, kept for debugging |

The cloud-init seed can hold a password, so it stays in a private work
folder, and the script deletes it after a good build. After a failed build,
the folder `.make-guest-image.*` keeps it for debugging; delete it when you
are done. Build one image per output directory at a time, because the logs
have fixed names.

It takes a few minutes and needs no root access. The host needs `curl`,
`sha256sum`, `ssh-keygen`, `timeout`, `qemu-img`, and one of `cloud-localds`,
`genisoimage`, `xorriso` or `mkisofs`. It uses the `qemu-system-x86_64` and
`qemu-img` next to it in `build-femu/` when they exist. If tools are missing,
the script names them. On Ubuntu:

```sh
sudo apt install curl cloud-image-utils
```

It also needs read and write access to `/dev/kvm` (see
[requirements.md](requirements.md#kvm-access)).

Options:

```sh
./make-guest-image.sh --size 64G                     # disk size (default 32G)
./make-guest-image.sh --ssh-key ~/.ssh/id_ed25519.pub
./make-guest-image.sh --password femu                # also allow console login
./make-guest-image.sh --cxl                          # also install ndctl, daxctl, cxl-cli
./make-guest-image.sh --packages build-essential,git # extra Ubuntu packages
./make-guest-image.sh -o /data/images                # another output directory
./make-guest-image.sh --force                        # replace an existing image
./make-guest-image.sh --kernel 6.12.40               # another guest kernel
./make-guest-image.sh --compress                     # smaller file, same content
./make-guest-image.sh --cache /data/cache            # share downloads
./make-guest-image.sh --base-serial latest           # newest cloud image
```

`./make-guest-image.sh --help` lists every option. The script refuses to
overwrite an existing image unless you pass `--force`. If provisioning fails,
read `provision.log` in the output directory.

Without `--password`, user `femu` has no password, so you can log in only over
SSH. The serial console in the run script's terminal shows the boot and a login
prompt you cannot use. Pass `--password` if you want console login too.

## Use an image in another place

Every `run-*.sh` script reads two variables:

- `IMGDIR`: the image directory (default `~/images`);
- `OSIMGF`: the image file (default `$IMGDIR/u20s.qcow2`).

<!-- femu-example: guest-image-osimgf -->
```bash
OSIMGF=/data/images/u20s.qcow2 ./run-blackbox.sh
```

`make-guest-image.sh` and `run-guest-ssh.sh` read `IMGDIR` too, so one
`export IMGDIR=/data/images` covers all three.

## Kernel per mode

The cloud image runs Linux 6.8. That covers NoSSD, BBSSD, ZNS, KV, CSD, FDP and
CXL. OCSSD needs a guest kernel older than 5.15, because Linux removed
LightNVM in 5.15. See [the kernel table](requirements.md#kernel-per-mode) for
every mode.

To run OCSSD with LightNVM, install an older release (Ubuntu 20.04 ships 5.4)
by hand as below, or use SPDK in the guest. `--kernel` below can install an
older kernel, but no test checks that its LightNVM driver works yet.

## Choose a kernel

`--kernel VERSION` installs one kernel and makes it the GRUB default:

| `VERSION` | Source | `uname -r` in the guest |
| --- | --- | --- |
| `distro` (default) | the cloud image kernel | `6.8.0-147-generic` for the pinned serial |
| Ubuntu ABI, such as `6.8.0-31` | the Ubuntu archive, `linux-image-6.8.0-31-generic` | `6.8.0-31-generic` |
| mainline, such as `6.12.40`, `6.12` or `6.13-rc3` | `https://kernel.ubuntu.com/mainline/v6.12.40/amd64/` | `6.12.40-061240-generic` |

```
 --kernel 6.12.40
   host:  CHECKSUMS --> image + modules debs (SHA-256 checked)
          --> ISO volume FEMUKERNEL
   guest: apt-get install the debs --> GRUB default = that kernel
   check boot: uname -r must be 6.12.40-061240-generic
```

A mainline version also needs `genisoimage`, `xorriso` or `mkisofs` on the
host, because the debs reach the guest on a small ISO volume.

Mainline builds come from the Ubuntu kernel team. They are unsigned, so
Secure Boot rejects them, and they get no security updates. Some versions
have no amd64 build; the script then names the version and stops. The
image gets no kernel headers, because recent mainline headers need a newer
C library than Ubuntu 24.04 has.

The SHA-256 of each deb comes from the `CHECKSUMS` file of the same server
over HTTPS. The script does not check the signature of that file. The
manifest records each deb and its digest.

## Pinned base image

The script pins one cloud image serial and its SHA-256, so two runs start
from the same bytes. Cloud-init installs the packages from the Ubuntu
archive of the build day, so an image is traceable, not reproducible.
`/var/lib/femu-guest/packages.txt` in the image lists every package version.

- `--base-serial latest` takes the newest cloud image instead. The script
  then trusts Ubuntu's SHA256 sums.
- `--base-serial YYYYMMDD` takes another serial from
  <https://cloud-images.ubuntu.com/releases/noble/>.
- `--base-sha256 HEX` adds a digest of your own. A mismatch stops the
  script before any boot.

If Ubuntu removes the pinned serial, the download fails with a message that
names `--base-serial latest`.

## Log in with SSH

The run scripts forward host port 8080 to the guest's SSH port. From
`build-femu/`, while a run script is running:

```sh
./run-guest-ssh.sh                  # interactive shell
./run-guest-ssh.sh sudo nvme list   # one command
```

`run-guest-ssh.sh` uses the key `$IMGDIR/femu-guest-key` and user `femu`. Set
`SSH_PORT`, `SSH_KEY` or `GUEST_USER` to change them. It skips host key
checks, because the guest is rebuilt often and listens only on localhost. The
plain equivalent is:

```sh
ssh -i ~/images/femu-guest-key -p 8080 femu@localhost
```

Only one guest can use a port at a time. To run a second guest, or when
another program holds 8080, set `SSH_PORT` for both the run script and
`run-guest-ssh.sh`:

<!-- femu-example: guest-image-ssh-port -->
```bash
SSH_PORT=8081 ./run-blackbox.sh        # terminal 1
SSH_PORT=8081 ./run-guest-ssh.sh       # terminal 2
```

## Alternatives

### Prebuilt image

The FEMU team shares a prebuilt Ubuntu 20.04 image on request through the
[FEMU VM image form](https://forms.gle/nEZaEe2fkj5B1bxt9). Extract it to
`~/images/` and rename it to `u20s.qcow2`. It holds Ubuntu 20.04; issue #57
reports Linux 5.4, which runs OCSSD but not ZNS. Log in with `ssh -p 8080 <user>@localhost`, using the account
described with the image.

### Install from an ISO

This needs a display for the installer.

<!-- femu-untested: installs a guest operating system from an ISO; needs KVM and an interactive installer -->
```bash
mkdir -p ~/images
cd ~/images
wget https://releases.ubuntu.com/24.04/ubuntu-24.04.3-live-server-amd64.iso
qemu-img create -f qcow2 u20s.qcow2 80G
qemu-system-x86_64 -enable-kvm -cpu host -smp 8 -m 8192 \
    -cdrom ubuntu-24.04.3-live-server-amd64.iso -boot d \
    -hda u20s.qcow2 -net nic -net user
```

If the ISO link has moved, pick the current one from
<https://releases.ubuntu.com>. Install `openssh-server`, `nvme-cli` and `fio`.

The run scripts use `-nographic`, so the guest must use the serial console.
Inside the installed guest, edit `/etc/default/grub`:

```
GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"
GRUB_TERMINAL="console serial"
GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200"
```

Then run `sudo update-grub` and power the guest off. Log in later with
`ssh -p 8080 <user>@localhost`.
