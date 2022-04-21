skiboot-5.1.12
--------------

skiboot-5.1.12 was released on Friday December 4th, 2015.

skiboot-5.1.12 is the 13th stable release of 5.1, it follows skiboot-5.1.11
(which was released November 13th, 2015).

Skiboot 5.1.12 contains bug fixes and a performance improvement.

opal-prd
^^^^^^^^

- Display an explict and obvious message if running on a system that does
  not support opal-prd, such as an IBM FSP based POWER system, where the
  FSP takes on the role of opal-prd.

pflash
^^^^^^

- Fix a missing (C) header
  - cherry-picked from master.

General
^^^^^^^

- Don't link with libgcc
  - On some toolchains, we don't have libgcc available.

POWER8 PHB (PCIe) specific
^^^^^^^^^^^^^^^^^^^^^^^^^^

- hw/phb3: Flush cache line after updating P/Q bits
    When doing an MSI EOI, we update the P and Q bits in the IVE. That causes
    the corresponding cache line to be dirty in the L3 which will cause a
    subsequent update by the PHB (upon receiving the next MSI) to get a few
    retries until it gets flushed.

    We improve the situation (and thus performance) by doing a dcbf
    instruction to force a flush of the update we do in SW.

    This improves interrupt performance, reducing latency per interrupt.
    The improvement will vary by workload.

IBM FSP based machines
^^^^^^^^^^^^^^^^^^^^^^

- FSP: Give up PSI link on shutdown
  This clears up some erroneous SRCs (error logs) in some situations.
- Correctly report back Real Time Clock errors to host
    Under certain rare error conditions, we could return an error code
    to the host OS that would cause current Linux kernels to get stuck
    in an infinite loop during boot.
    This was introduced in skiboot-5.0-rc1.
