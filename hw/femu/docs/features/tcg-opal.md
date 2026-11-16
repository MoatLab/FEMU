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

## MEK Multiparty Authorization (x-opal-mpa)

`x-opal-mpa=on`, with `x-opal=on`, adds the TCG MEK Multiparty
Authorization feature set 1.00 to the Locking SP. A range key then needs
the access keys of one or two parties. The feature is experimental and
off by default.

```
 host party A, B
   Get Certificate1 (KEM key), check its signature with Certificate2
   HPKE Seal(KEM key, info = method UID || AC UID, access key)
     --> InitializeAccessCondition, EnableAccess, TestAccessKey,
         ChangeAccessKey, DisableAccess on AccessCondition1 to 4
   Set PendingAccessConditions of K_AES_256 row r, then GenKey r
     --> ActiveAccessConditions of r = the new list, old data erased
 range r: read and write only while every AC in its Active list is enabled
```

- The HPKE suite is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
  ChaCha20-Poly1305. The HPKEIdentifiers extension of Certificate1 names
  it.
- Certificate1 holds the KEM key. It is X.509 v3 DER, signed by the
  Ed25519 key of Certificate2. Each Activate, each Certificate1 GenKey
  and each power cycle make a new KEM key.
- Certificate1 has keyUsage keyEncipherment and keyAgreement. MPA asks
  for the first and RFC 8410 for the second.
- The CertificateData UID of Certificate2 follows MPA Table 12. MPA
  Table 11 gives another UID for the same row.
- Level 0 feature 040Ch reports 4 AccessConditions, 2 per key and an
  Access Key Length of 48 bytes. The 48 bytes are the 32-byte key plus
  the AEAD tag.
- The TPer keeps no access key. A random AC secret is sealed under it,
  and EnableAccess checks the key by opening that seal.

Lock rules:

| Event | Effect on a range r that names the AC in its Active list |
| --- | --- |
| DisableAccess, or a reset in DisableAccessOnReset | ReadLocked and WriteLocked set; they stay set |
| EnableAccess | no unlock; the host must Set ReadLocked and WriteLocked to False |
| Set ReadLocked or WriteLocked to False | NOT_AUTHORIZED while an AC in the list is disabled |
| Set ReadLockEnabled or WriteLockEnabled to False | FAIL |
| GenKey with an AC disabled | the old data goes; no access until every AC is enabled |
| a power cycle | every AC disabled, ranges locked, a new KEM key; the seals stay |
| Format crypto erase, Sanitize Crypto Erase | new keys; the lists and the AC state stay |

- The methods read and change the working image of a transaction. An
  abort restores the AC state too.
- A wrong access key in EnableAccess gives FAIL. MPA also allows
  INVALID_PARAMETER there.
- RevertSP with KeepGlobalRangeKey fails with INVALID_PARAMETER while the
  Global key has an Active list.
- This crypto is for emulation only. It is not constant time, and the
  identity key has no vendor root.

## Limits

x-opal works with one NoSSD or page-mapped BlackBox namespace without
metadata. These properties refuse it: a femu-subsys, CXL, CSD, `ns_mgmt`,
`power_loss`, `sanitize_ns`, `ns_wp` and `persist_file` settings. The
state lives in memory, so it ends with QEMU. `x-opal-mpa` needs
`x-opal`.

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
