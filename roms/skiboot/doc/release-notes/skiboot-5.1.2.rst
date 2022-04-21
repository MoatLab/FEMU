skiboot-5.1.2
-------------

skiboot-5.1.2 was released on September 9th, 2015.

skiboot-5.1.2 is the third stable release of 5.1, it follows skiboot-5.1.1
(which was released August 18th, 2015).

Skiboot 5.1.2 contains all fixes from skiboot-5.1.1 and is a minor bugfix
release.

Changes
^^^^^^^
Over skiboot-5.1.1, we have the following changes:

- phb3: Handle fence in phb3_pci_msi_check_q to fix hang

  If the PHB is fenced during phb3_pci_msi_check_q, it can get stuck in an
  infinite loop waiting to lock the FFI. Further, as the phb lock is held
  during this function it will prevent any other CPUs from dealing with
  the fence, leading to the entire system hanging.

  If the PHB_FFI_LOCK returns all Fs, return immediately to allow the
  fence to be dealt with.
- phb3: Continue CAPP setup even if PHB is already in CAPP mode
  This fixes a critical bug in CAPI support.
- Platform hook for terminate call

  - on assert() or other firmware failure, we will make a SEL callout
    on ASTBMC platforms
  - (slight) refactor of code for IBM-FSP platforms

- refactor slot naming code
- Slot names for Habanero platform
- misc improvements in userspace utilities (incl pflash, gard)
- build improvements

  - fixes for two compiler warnings were squashed in 5.1.1 commit,
    re-introduce the fixes.
  - misc compiler/static analysis warning fixes

- gard utility:

  - If gard tool detects the GUARD PNOR partition is corrupted, it will
    pro-actively re-initialize it.
    Modern Hostboot is more sensitive to the content of the GUARD partition
    in order to boot.
  - Update record clearing to match Hostboots expectations
    We now write ECC bytes throughout the whole partition.
    Without this fix, hostboot may not bring up the machine.
  - In the event of a corrupted GUARD partition so that even the first entry
    cannot be read, the gard utility now provides the user with the option
    to wipe the entirety of the GUARD partition to attempt recovery.

- opal_prd utility:

  - Add run command to pass through commands to HostBoot RunTime (HBRT)

    - this is for OpenPower firmware developers only.

  - Add htmght-passthru command.

    - this is for OpenPower firmware developers only.

  - Add override interface to pass attribute-override information to HBRT.
  - Server sends response in error path, so that client doesn't block forever

- external/mambo tcl scripts

  - Running little-endian kernels in mambo requires HILE to be set properly,
    which requires a bump in the machine's pvr value to a DD2.x chip.

Stats
^^^^^
For skiboot-5.1.0 to 5.1.2:
Processed 67 csets from 11 developers
1 employers found
A total of 2258 lines added, 784 removed (delta 1474)

Developers with the most changesets

=========================== ==========
=========================== ==========
Stewart Smith               24 (35.8%)
Cyril Bur                   18 (26.9%)
Vasant Hegde                 8 (11.9%)
Neelesh Gupta                5 (7.5%)
Benjamin Herrenschmidt       5 (7.5%)
Daniel Axtens                2 (3.0%)
Samuel Mendoza-Jonas         1 (1.5%)
Vaidyanathan Srinivasan      1 (1.5%)
Vipin K Parashar             1 (1.5%)
Ian Munsie                   1 (1.5%)
Michael Neuling              1 (1.5%)
=========================== ==========

Developers with the most changed lines

========================== ===========
========================== ===========
Cyril Bur                  969 (42.5%)
Neelesh Gupta              433 (19.0%)
Benjamin Herrenschmidt     304 (13.3%)
Vasant Hegde               236 (10.3%)
Stewart Smith              163 (7.1%)
Vaidyanathan Srinivasan    135 (5.9%)
Vipin K Parashar             8 (0.4%)
Ian Munsie                   8 (0.4%)
Daniel Axtens                2 (0.1%)
Michael Neuling              2 (0.1%)
Samuel Mendoza-Jonas         1 (0.0%)
========================== ===========

Developers with the most lines removed

========================== ==========
========================== ==========
Daniel Axtens                2 (0.3%)
Michael Neuling              1 (0.1%)
========================== ==========

Developers with the most signoffs (total 44)

========================== ==========
========================== ==========
Stewart Smith               43 (97.7%)
Neelesh Gupta                1 (2.3%)
========================== ==========

Developers with the most reviews (total 8)

========================== ==========
========================== ==========
Patrick Williams             5 (62.5%)
Samuel Mendoza-Jonas         3 (37.5%)
========================== ==========

Developers with the most test credits (total 0)

Developers who gave the most tested-by credits (total 0)

Developers with the most report credits (total 1)

========================== ==========
========================== ==========
Benjamin Herrenschmidt       1 (100.0%)
========================== ==========

Developers who gave the most report credits (total 1)

========================== ==========
========================== ==========
Samuel Mendoza-Jonas         1 (100.0%)
========================== ==========

Top changeset contributors by employer

========================== ==========
========================== ==========
IBM                         67 (100.0%)
========================== ==========

Top lines changed by employer

========================= ==========
========================= ==========
IBM                       2281 (100.0%)
========================= ==========

Employers with the most signoffs (total 44)

========================== ==========
========================== ==========
IBM                         44 (100.0%)
========================== ==========

Employers with the most hackers (total 11)

========================== ==========
========================== ==========
IBM                         11 (100.0%)
========================== ==========
