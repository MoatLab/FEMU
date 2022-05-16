Memory in skiboot
=================

There are regions of memory we statically allocate for firmware as well as
a HEAP region for boot and runtime allocations.

A design principle of skiboot is to attempt not to allocate memory at runtime,
or at least keep it to a minimum, and not do so in any critical code path
for the system to remain running.

At no point during runtime should a skiboot memory allocation failure cause
the system to stop functioning.

HEAP
----

Dynamic memory allocations go in a single heap. This is identified as
Region ibm,firmware-heap and appears as a reserved section in the device tree.

Originally, it was 12582912 bytes in size (declared in mem_map.h).
Now, it is 13631488 bytes after being bumped as part of the GCOV work.

We increased heap size as on larger systems, we were getting close to using
all the heap once skiboot became 2MB with GCOV.

Heap usage is printed before running the payload.

For example, as of writing, on a dual socket Tuleta: ::

  [45215870591,5] SkiBoot skiboot-5.0.1-94-gb759ce2 starting...
  [3680939340,5] CUPD: T side MI Keyword = SV830_027
  [3680942658,5] CUPD: T side ML Keyword = FW830.00
  [15404383291,5] Region ibm,firmware-heap free: 5378072

and on a palmetto: ::

  [24748502575,5] SkiBoot skiboot-5.0.1-94-gb759ce2 starting...
  [9870429550,5] Region ibm,firmware-heap free: 10814856

Our memory allocator is simple, a use pattern of: ::

  A = malloc();
  B = malloc();
  free(A);

is likely to generate fragmentation, so it should generally be avoided
where possible.
