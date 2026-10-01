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

1. downloads the Ubuntu 24.04 cloud image and checks it against Ubuntu's
   SHA256 sums (and their GPG signature when `gpgv` and the Ubuntu cloud-image
   keyring are installed);
2. boots it once without a display to create user `femu` with passwordless
   `sudo`, install `nvme-cli` and `fio`, and turn on the serial console;
3. powers the guest off and writes the result.

It writes these files to `~/images/`:

| File | Purpose |
| --- | --- |
| `u20s.qcow2` | The guest disk the run scripts boot |
| `femu-guest-key`, `femu-guest-key.pub` | SSH key for user `femu` |
| `cache/` | The downloaded cloud image, reused on the next run |
| `seed.iso`, `provision.log` | Provisioning input and serial log, kept for debugging |

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
by hand as below, or use SPDK in the guest.

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
