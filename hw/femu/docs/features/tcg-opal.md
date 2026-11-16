# TCG Opal self-encrypting drive (x-opal)

`x-opal=on` makes FEMU answer as a TCG Opal 2 drive. The guest sends TCG
commands with NVMe Security Send (81h) and Security Receive (82h). The
feature is experimental and off by default. It is not yet conformant, so
do not use it to certify host software.

FEMU encrypts no data. A new key is modelled as an erase: the LBAs that
get a new key read back as zeros.

## What it models

```
 guest (sedutil, nvme-cli)
   | Security Send / Receive (SECP 01h, 02h)
   v
 TPer: ComID 1000h, sessions, transactions
   |-- Admin SP:   MSID, SID, PSID, Activate, Revert, Block SID
   `-- Locking SP: 8 ranges + Global, keys, ACEs, users,
                   MBR control, MBR table (128 MiB), DataStore (10 MiB)
                         |
                         | lock view (copy, published while I/O is stopped)
                         v
 I/O path: Read, Write, Write Zeroes, Write Uncorrectable,
           Compare, Verify, DSM with AD, Copy
```

- MSID and PSID are `FEMU-MSID-` and `FEMU-PSID-` plus the controller
  serial.
- The Locking SP has 8 ranges, 4 admins and 8 users.
- GenKey, a new range start or length, and a Revert erase the LBAs that
  change owner or key.
- Byte-table writes in a transaction keep an undo copy, at most 256
  chunks of 64 KiB.

## Lock checks

| Command | Rule | Result when refused |
| --- | --- | --- |
| Write, Write Zeroes, Write Uncorrectable, DSM with AD | a write-locked owner | Access Denied (2/86h), DNR |
| Read | a read-locked owner | Access Denied; zeros when the MBR shadow is active and all owners are read locked |
| Compare, Verify | a read-locked owner | Access Denied |
| Copy | a read-locked source or a write-locked destination | Access Denied; Dword 0 names the source |
| Flush | none | |

A command whose LBAs cross two owners takes the strictest rule.

## MBR shadow

While MBR Enable is set and MBR Done is clear, LBAs below the MBR size
read the MBR table bytes. A Write there is refused. A Read ignores the
locks, but Compare, Verify and a Copy source need unlocked owners. Set
MBR Done to read the media again.

```
 Read LBA x
   x < MBR size and shadow on? --yes--> MBR table bytes (one page read time)
           | no
           v
   owners read locked? --yes--> shadow on and all locked? --> zeros
           | no                         | no --> Access Denied
           v
         media
```

## Admin commands and resets

- Format NVM is refused with Invalid Format (1/0Ah), DNR, when a formatted
  LBA has a write-locked owner.
- Format NVM offers a cryptographic erase (FNA bit 2, SES 010b). It
  clears the data, as a user data erase does, and gives every range a
  new key. The PINs, ACEs and ranges stay. A Sanitize Crypto Erase also
  gives new keys.
- An open transaction keeps the new keys. A GenKey that it holds still
  erases its range at the commit.
- Sanitize is refused with Access Denied, DNR, while the Locking SP is
  active.
- Copy accepts descriptor format 0h only; OCFS reports it.
- A machine reset (QMP `system_reset`, a guest reboot) is a TCG Hardware
  Reset. The session ends, and Block SID clears when its Hardware Reset
  bit was set. Authentication tries stay.
- An FLR, a PCIe hot reset and a controller reset are no TCG reset.
- TPER_RESET applies the programmatic reset type to LockOnReset and
  DoneOnReset.

## Limits

x-opal works with one NoSSD or page-mapped BlackBox namespace without
metadata. These properties refuse it: a femu-subsys, CXL, CSD, `ns_mgmt`,
`power_loss`, `sanitize_ns`, `ns_wp` and `persist_file` settings. The
state lives in memory, so it ends with QEMU.

## Example

<!-- femu-untested: x-opal is an experimental property; the opal qtests start this device -->
```
-device femu,devsz_mb=1024,femu_mode=2,x-opal=on,serial=sed0
```

In the guest, `sedutil-cli --scan` lists the drive. This command reads
Level 0 discovery:

```
nvme security-recv /dev/nvme0 -p 1 -s 1 -t 2048
```
