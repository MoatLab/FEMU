ibm,firmware-versions node
==========================

The `ibm,firmware-versions` node contains information on the versions of
various firmware components as they were **during boot**. It **does not**
change if there are pending or runtime updates. It represents (to the best
of boot firmware's ability) what versions of firmware were during this boot.

================= ======== ============================================
Property          Required Value
================= ======== ============================================
version           POWER9   See below
skiboot           N        component version number
occ               N        component version number
buildroot         N        component version number
capp-ucode        N        component version number
petitboot         N        component version number
open-power        N        component version number
hostboot-binaries N        component version number
MACHINE-xml       N        MACHINE (e.g. habanero) machine XML version
hostboot          N        component version number
linux             N        component version number
================= ======== ============================================

``version`` property
^^^^^^^^^^^^^^^^^^^^

This property **must** exist on POWER9 and above systems. It **may** exist
on POWER8 systems.

If this property exists, it **must** conform to this specification.
It's a single version number of the firmware image. In the event of a system
supporting multiple firmware sides, this represents the **default** boot side.
That is, the version that is applicable when determining if a machine
requires a firmware update.

Examples (for three different platforms):

- ``IBM-sandwich-20170217``
- ``open-power-habanero-v1.14-45-g78d89280c3f9-dirty``
- ``open-power-SUPERMICRO-P8DTU-V2.00.GA2-20161028``

To compare two versions (for the purpose of determining if the current
installed firmware is in need of updating to the one being compared against)
we need a defined set of rules on how to do this comparison.

Version numbers are **not** intended to be compared across platforms.

The version string may include a description at the start of it. This
description can contain any set of characters but **must not** contain
a '-' followed by a digit. It also **must not** contain '-v' or '-V' followed
by a digit.

Each part of the version string is separated by a '-' character. Leading
sections are ignored, until one starts with a digit (0-9) or a 'v' or 'V',
followed by a digit. Where there is a leading 'v' or 'V', it is also stripped.

For the above three examples, we'd be left with:

- ``20170217``
- ``1.14-45-g78d89280c3f9-dirty``
- ``2.00.GA2-20161028``

Each section is now compared until a difference is found. All comparisons
are done *lexically*. The lexical comparison sorts in this order: tilde (~),
all letters, non-letters. The tilde is special and sorts before an end of part.
This allows the common usage of designating pre-release builds by a tailing
section beginning with a '~'.

For example: "1.0~20170217", "1.0~rc4" and "1.0~beta1" all sort
**before** "1.0"

Note that "1.0beta" sorts **after** "1.0"

The start of the version string contains an optional *epoch*. If not present,
it is zero. This allows a reset of versioning schemes. All versions with an
epoch of N+1 are greater than those with epoch N, no matter what the version
strings would compare. For example "0:4.0" is **less** than "1:1.0". Increasing
the epoch should **not** be a regular occurance.

For the remainder of the version strings, each part (separated by '.' or '-')
is compared lexically. There are two exceptions: any part beginning with "-g"
or "-p" followed by a hexadecimal string is compared as a string, and if they
are different the versions are determined to be different. For example, the
sections "-g78d89280c3f9" and "-g123456789abc" differ and for all comparisons
(less than, greater than, equal) the result should be true.

For those who have been paying attention, this scheme should look very
familiar to those who are familiar with RPM and Debian package versioning.

The below table shows comparisons between versions and what the result should
be:

=========================== =========================== ====================
A                           B                           Result
=========================== =========================== ====================
1.14-45-g78d89280c3f9-dirty 1.14-45-g78d89280c3f9-dirty Equal
1.14-45-g78d89280c3f9-dirty 1.14-45-g78d89280c3f9       A > B
1.14-45-g78d89280c3f9-dirty 1.14-45-g123456789abc       A < B, A > B, A != B
1.14-45-g78d89280c3f9-dirty 1.14-46                     A < B
1.14-45-g78d89280c3f9-dirty 1.15                        A < B
1.14-45-g78d89280c3f9-dirty 1:1.0                       A < B
1.0                         1.0~daily20170201           A > B
1.0.1                       1.0~daily20170201           A > B
1.0                         1.0.1                       A < B
1.0                         1.0beta                     A < B
=========================== =========================== ====================

Examples
^^^^^^^^

New style (required for POWER9 and above):

.. code-block:: dts

   ibm,firmware-versions {
		version = "open-power-habanero-v1.14-45-g78d89280c3f9-dirty";
		skiboot = "5.4.0";
		occ = "d7efe30";
		linux = "4.4.32-openpower1";
   };

Old-style:

.. code-block:: dts

        ibm,firmware-versions {
                occ = "d7efe30-opdirty";
                skiboot = "5.4.0-opdirty";
                buildroot = "211bd05";
                capp-ucode = "1bb7503-opdirty";
                petitboot = "v1.3.1-opdirty-d695626";
                open-power = "habanero-f7b8f65-dirty";
                phandle = <0x1000012e>;
                hostboot-binaries = "56532f5-opdirty";
                habanero-xml = "6a78496-opdirty-526ff79";
                hostboot = "09cfacb-opdirty";
                linux = "4.4.32-openpower1-opdirty-85cf528";
        };
