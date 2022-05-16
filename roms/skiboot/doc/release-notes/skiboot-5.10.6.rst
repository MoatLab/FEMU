.. _skiboot-5.10.6:

==============
skiboot-5.10.6
==============

skiboot 5.10.6 was released on Monday May 28th, 2018. It replaces
:ref:`skiboot-5.10.5` as the current stable release in the 5.10.x series.

It is recommended that 5.10.6 be used instead of any previous 5.10.x version,
especially due to the locking bug fixes.

It is expected that this will be the final 5.10.x version, with 6.0.x taking
over as the main stable branch.

Over :ref:`skiboot-5.10.5`, we have the following fixes:

- opal-prd: Do not error out on first failure for soft/hard offline.

  The memory errors (CEs and UEs) that are detected as part of background
  memory scrubbing are reported by PRD asynchronously to opal-prd along with
  affected memory ranges. hservice_memory_error() converts these ranges into
  page granularity before hooking up them to soft/hard offline-ing
  infrastructure.

  But the current implementation of hservice_memory_error() does not hookup
  all the pages to soft/hard offline-ing if any of the page offline action
  fails. e.g hard offline can fail for:

  - Pages that are not part of buddy managed pool.
  - Pages that are reserved by kernel using memblock_reserved()
  - Pages that are in use by kernel.

  But for the pages that are in use by user space application, the hard
  offline marks the page as hwpoison, sends SIGBUS signal to kill the
  affected application as recovery action and returns success.

  Hence, It is possible that some of the pages in that memory range are in
  use by application or free. By stopping on first error we loose the
  opportunity to hwpoison the subsequent pages which may be free or in use by
  application. This patch fixes this issue.
- xive: fix missing unlock in error path

  Found with sparse and some added lock annotations.
- OPAL_PCI_SET_POWER_STATE: fix locking in error paths

  Otherwise we could exit OPAL holding locks, potentially leading
  to all sorts of problems later on.
