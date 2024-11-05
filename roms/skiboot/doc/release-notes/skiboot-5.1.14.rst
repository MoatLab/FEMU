skiboot-5.1.14
--------------

skiboot-5.1.14 was released on Wed March 9th, 2016.

skiboot-5.1.14 is the 15th stable release of 5.1, it follows skiboot-5.1.13
(which was released January 27th, 2016). This release contains a spelling
fix in a log message and an added device tree property to enable older
kernels (with bootloader support) to use a framebuffer that is redirected
to the BMC VGA port.

As such, skiboot-5.1.14 has no advantage over skiboot-5.1.13 unless you
are wanting the neat offb framebuffer trick.

Changes are:

- fsp: fix spelling of "advertise" in log message
  See: https://www.youtube.com/watch?v=8Gv0H-vPoDc
- Explicit 1:1 mapping in ranges properties have been added to PCI
  bridges. This allows a neat trick with offb and VGA ports that should
  probably not be told to young children.
