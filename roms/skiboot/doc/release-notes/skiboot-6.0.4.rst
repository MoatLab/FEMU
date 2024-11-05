.. _skiboot-6.0.4:

=============
skiboot-6.0.4
=============

skiboot 6.0.4 was released on Monday May 28th, 2018. It replaces
:ref:`skiboot-6.0.3` as the current stable release in the 6.0.x series.

It is recommended that 6.0.4 be used instead of any previous 6.0.x version.

Over :ref:`skiboot-6.0.3`, we have two bug fixes: one helps with performance
(especially in HPC environments), and one is an opal-prd fix.

Changes are:

- SLW: Remove stop1_lite and stop2_lite

  stop1_lite has been removed since it adds no additional benefit
  over stop0_lite. stop2_lite has been removed since currently it adds
  minimal benefit over stop2. However, the benefit is eclipsed by the time
  required to ungate the clocks

  Moreover, Lite states don't give up the SMT resources, can potentially
  have a performance impact on sibling threads.

  Since current OSs (Linux) aren't smart enough to make good decisions
  with these stop states, we're (temporarly) removing them from what
  we expose to the OS, the idea being to bring them back in a new
  DT representation so that only an OS that knows what to do will
  do things with them.
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
