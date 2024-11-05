skiboot-5.2.3
=============

skiboot-5.2.3 was released on Thursday June 30th, 2016.

skiboot-5.2.3 is the 4th stable release of skiboot 5.2, the new stable
release of skiboot, which takes over from the 5.1.x series which was
first released August 17th, 2015.

Skiboot 5.2.3 replaces skiboot-5.2.2 as the current stable version, which was
released on May 5th, 2016. Over skiboot-5.2.2, skiboot 5.2.3 contains
one important bug fix regarding parsing data from the OCC regarding CPU
frequency tables, which could lead to no CPU frequency scaling.

skiboot-5.2.3 contains all bug fixes as of skiboot-5.1.16.

This is the second release that will follow the (now documented) Skiboot
stable rules - see :ref:`stable-rules`.

Over skiboot-5.2.2, the following fixes are included:

OpenPOWER platforms
^^^^^^^^^^^^^^^^^^^

- occ: Filter out entries from Pmin to Pmax in pstate table
  (cherry picked from commit eca02ee2e62cee115d921a01cea061782ce47cc7)
  Without this fix, with newer OCC firmware on some OpenPOWER machines,
  we would fail to parse the table from the OCC, which meant the host OS
  would not get a table of supported CPU frequencies.

General
^^^^^^^

- pci: Do a dummy config write to devices to establish bus number
  (cherry picked from commit f46c1e506d199332b0f9741278c8ec35b3e39135)

    On PCI Express, devices need to know their own bus number in order
    to provide the correct source identification (aka RID) in upstream
    packets they might send, such as error messages or DMAs.

    However while devices know (and hard wire) their own device and
    function number, they know nothing about bus numbers by default, those
    are decoded by bridges for routing. All they know is that if their
    parent bridge sends a "type 0" configuration access, they should decode
    it provided the device and function numbers match.

    The PCIe spec thus defines that when a device receive such a configuration
    access and it's a write, it should "capture" the bus number in the source
    field of the packet, and re-use as the originator bus number of all
    subsequent outgoing requests.

    In order to ensure that a device has this bus number firmly established
    before it's likely to send error packets upstream, we should thus do a
    dummy configuration write to it as soon as possible after probing.
- Fix GCC 6 warning in backtrace code
  (cherry picked from commit 793f6f5b32c96f2774bd955b6062c74a672317ca)
- Backport of user visible typo fixes
  partial cherry picked from 4c95b5e04e3c4f72e4005574f67cd6e365d3276f

Utilities
^^^^^^^^^

- Fix ARM build failure with parallel make
