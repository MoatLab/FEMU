skiboot-5.1.4
-------------

skiboot-5.1.4 was released on September 26th, 2015.

skiboot-5.1.4 is the 5th stable release of 5.1, it follows skiboot-5.1.3
(which was released September 15th, 2015).

Skiboot 5.1.4 contains all fixes from skiboot-5.1.3 and is an important bug
fix release and a strongly recommended update from any prior skiboot-5.1.x
release.

Changes
^^^^^^^
Over skiboot-5.1.3, we have the following changes:

- Rate limit OPAL_MSG_OCC to only one outstanding message to host

  In the event of a lot of OCC events (or many CPU cores), we could
  send many OCC messages to the host, which if it wasn't calling
  opal_get_msg really often, would cause skiboot to malloc() additional
  messages until we ran out of skiboot heap and things didn't end up
  being much fun.

  When running certain hardware exercisers, they seem to steal all time
  from Linux being able to call opal_get_msg, causing these to queue up
  and get "opalmsg: No available node in the free list, allocating" warnings
  followed by tonnes of backtraces of failing memory allocations.

- Ensure reserved memory ranges are exposed correctly to host
  (fix corrupted SLW image)

  We seem to have not hit this on ASTBMC based  OpenPower machines, but was
  certainly hit on FSP based machines
