.. _skiboot-5.4.10:

==============
skiboot-5.4.10
==============

skiboot-5.4.10 was released on Monday May 28th, 2018. It replaces
:ref:`skiboot-5.4.9` as the current stable release in the 5.4.x series.

Over :ref:`skiboot-5.4.9`, we have a few bug fixes:

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
- OPAL_PCI_SET_POWER_STATE: fix locking in error paths

  Otherwise we could exit OPAL holding locks, potentially leading
  to all sorts of problems later on.
- p8-i2c: Limit number of retry attempts

  Current we will attempt to start an I2C transaction until it succeeds.
  In the event that the OCC does not release the lock on an I2C bus this
  results in an async token being held forever and the kernel thread that
  started the transaction will block forever while waiting for an async
  completion message. Fix this by limiting the number of attempts to
  start the transaction.
- FSP/CONSOLE: Disable notification on unresponsive consoles

  Commit fd6b71fc fixed the situation where ipmi console was open (hvc0) but got
  data on different console (hvc1).

  During FSP R/R OPAL closes all consoles. After R/R complete FSP requests to
  open hvc1 and sends data on this. If hvc1 registration failed or not opened in
  host kernel then it will not read data and results in RCU stalls.

  Note that this is workaround for older kernel where we don't have separate irq
  for each console. Latest kernel works fine without this patch.
