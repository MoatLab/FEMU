.. _skiboot-6.7:

skiboot-6.7
===========

skiboot v6.7 was released on Tuesday November 3rd 2020. It is the first release
of skiboot 6.7 series, which becomes the new stable release following the
:ref:`skiboot-6.6` release, first released Wednesday April 22nd 2020.

The main reason for this release is the addition of secure variable support and
the Mowgli platform. Aside from these feature, this release is largely bug-fixes.
However, this is expected since we're approaching the end of the P9 product cycle
and development has largely shifted towards enabling a future processor with a
difficult-to-guess name.

.. _skiboot-6.7-new-features:

New features
------------

- Secure Variable support

  The secure variable API provides the host operating system with space to
  store cryptographic keys for OS secure boot. The security comes from the
  requirement that all secure variable updates be cryptographically signed
  so the keys used to verify the secure boot chain can only be updated by
  a user authorized to do so.

- Fleetwood platform support

  Support was added for the multi-node IBM Fleetwood systems. This support
  was largely for internal IBM testing purposes and is not, and will not, ever
  be offically supported.

- Mowgli platform support

  Support was added for the Mowgli platform built by Wistron.
