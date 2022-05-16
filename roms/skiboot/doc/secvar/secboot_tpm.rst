.. _secvar/secboot_tpm:

secboot_tpm secvar storage driver for P9 platforms
==================================================

Overview
--------

This storage driver utilizes the SECBOOT PNOR partition and TPM NV space to
persist secure variables across reboots in a tamper-resistant manner. While
writes to PNOR cannot be completely prevented, writes CAN be prevented to TPM
NV. On the other hand, there is limited available space in TPM NV.

Therefore, this driver uses both in conjunction: large variable data is written
to SECBOOT, and a hash of the variable data is stored in TPM NV. When the
variables are loaded from SECBOOT, this hash is recalculated and compared
against the value stored in the TPM. If they do not match, then the variables
must have been altered and are not loaded.

See the following sections for more information on the internals of the driver.


Storage Layouts
---------------

At a high-level, there are a few major logical components:

 - (PNOR) Variable storage (split in half, active/staging)
 - (PNOR) Update storage
 - (TPM)  Protected variable storage
 - (TPM)  Bank hashes & active bit

Variable storage consists of two smaller banks, variable bank 0 and variable
bank 1. Either of the banks may be designated "active" by setting the active
bank bit to either 0 or 1, indicating that the corresponding bank is now
"active". The other bank is then considered "staging". See the "Persisting
Variable Bank Updates" for more on the active/staging bank logic.

Protected variable storage is stored in ``VARS`` TPM NV index. Unlike the other
variable storage, there is only one bank due to limited storage space. See the
TPM NV Indices section for more.


Persisting the Variable Bank
----------------------------

When writing a new variable bank to storage, this is (roughly) the procedure the
driver will follow:

1. write variables to the staging bank
2. calculate hash of the staging bank
3. store the staging bank hash in the TPM NV
4. flip the active bank bit

This procedure ensures that the switch-over from the old variables to the
new variables is as atomic as possible. This should prevent any possible
issues caused by an interruption during the writing process, such as power loss.

The bank hashes are a SHA256 hash calculated over the whole region of
storage space allocated to the bank, including unused storage. For consistency,
unused space is always written as zeroes. Like the active/staging variable
banks, there are also two corresponding active/staging bank hashes stored in
the TPM.


TPM NV Indices
--------------

The driver utilizes two TPM NV indices:

.. code-block:: c

  # size). datadefine SECBOOT_TPMNV_VARS_INDEX	0x01c10190
  #define SECBOOT_TPMNV_CONTROL_INDEX	0x01c10191

The ``VARS`` index stores variables flagged with ``SECVAR_FLAG_PROTECTED``.
These variables are critical to the state of OS secure boot, and therefore
cannot be safely stored in the SECBOOT partition. This index is defined to be
1024 bytes in size, which is enough for the current implementation on P9. It
is kept small by default to preserve the very limited NV index space.

The ``CONTROL`` index stores the bank hashes, and the bit to determine which
bank is active. See the Active/Staging Bank Swapping section for more.

Both indices are defined on first boot with the same set of attributes. If the
indices are already defined but not in the expected state, (different
attributes, size, etc), then the driver will halt the boot. Asserting physical
presence will redefine the indices in the correct state.


Locking
-------

PNOR cannot be locked, however the TPM can be. The TPM NV indices are double
protected via two locking mechanisms:

 - The driver's ``.lock()`` hook sends the ``TSS_NV_WriteLock`` TPM command.
This sets the ``WRITELOCKED`` attribute, which is cleared on the next
TPM reset.

 - The TPM NV indices are defined under the platform hierarchy. Skiboot will add
a global lock to all the NV indices under this hierarchy prior to loading a
kernel. This is also reset on the next TPM reset.

NOTE: The TPM is only reset during a cold reboot. Fast reboots or kexecs will
NOT unlock the TPM.


Resetting Storage / Physical Presence
-------------------------------------

In the case that secure boot/secvar has been rendered unusable, (for example:
corrupted data, lost/compromised private key, improperly defined NV indices, etc)
this storage driver responds to physical presence assertion as a last-resort
method to recover the system.

Asserting physical presence undefines, and immediately redefines the TPM NV
indices. Defining the NV indices then causes a cascading set of reformats for
the remaining components of storage, similar to a first-boot scenario.

This driver considers physical presence to be asserted if any of the following
device tree nodes are present in ``ibm,secureboot``:
 - ``clear-os-keys``
 - ``clear-all-keys``
 - ``clear-mfg-keys``


Storage Formats/Layouts
=======================

SECBOOT (PNOR)
--------------

Partition Format:
 - 8b secboot header
   - 4b: u32. magic number, always 0x5053424b
   - 1b: u8. version, always 1
   - 3b: unused padding
 - 32k: secvars. variable bank 0
 - 32k: secvars. variable bank 1
 - 32k: secvars. update bank

Variable Format (secvar):
 - 8b: u64. key length
 - 8b: u64. data size
 - 1k: string. key
 - (data size). data

TPM VARS (NV)
-------------

NV Index Format:
 - 8b secboot header
   - 4b: u32. magic number, always 0x5053424b
   - 1b: u8. version, always 1
   - 3b: unused padding
 - 1016b: packed secvars. protected variable storage

Variable Format (packed secvar):
 - 8b: u64. key length
 - 8b: u64. data size
 - (key length): string. key
 - (data size). data

TPM CONTROL (NV)
----------------

 - 8b secboot header
   - 4b: u32. magic number, always 0x5053424b
   - 1b: u8. version, always 1
   - 3b: unused padding
 - 1b: u8. active bit, 0 or 1
 - 32b: sha256 hash of variable bank 0
 - 32b: sha256 hash of variable bank 1

