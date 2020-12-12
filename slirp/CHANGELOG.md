# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Deprecated

### Fixed

## [4.2.0] - 2020-03-17

### Added

 - New API function `slirp_add_unix`: add a forward rule to a Unix socket.
 - New API function `slirp_remove_guestfwd`: remove a forward rule previously
   added by `slirp_add_exec`, `slirp_add_unix` or `slirp_add_guestfwd`
 - New SlirpConfig.outbound_addr{,6} fields to bind output socket to a
   specific address

### Changed

 - socket: do not fallback on host loopback if get_dns_addr() failed
   or the address is in slirp network

### Fixed

 - ncsi: fix checksum OOB memory access
 - `tcp_emu()`: fix OOB accesses
 - tftp: restrict relative path access
 - state: fix loading of guestfwd state

## [4.1.0] - 2019-12-02

### Added

 - The `slirp_new()` API, simpler and more extensible than `slirp_init()`.
 - Allow custom MTU configuration.
 - Option to disable host loopback connections.
 - CI now runs scan-build too.

### Changed

 - Disable `tcp_emu()` by default. `tcp_emu()` is known to have caused
   several CVEs, and not useful today in most cases. The feature can
   be still enabled by setting `SlirpConfig.enable_emu` to true.
 - meson build system is now `subproject()` friendly.
 - Replace remaining `malloc()`/`free()` with glib (which aborts on OOM)
 - Various code cleanups.

### Deprecated

 - The `slirp_init()` API.

### Fixed

 - `getpeername()` error after `shutdown(SHUT_WR)`.
 - Exec forward: correctly parse command lines that contain spaces.
 - Allow 0.0.0.0 destination address.
 - Make host receive broadcast packets.
 - Various memory related fixes (heap overflow, leaks, NULL
   dereference).
 - Compilation warnings, dead code.

## [4.0.0] - 2019-05-24

### Added

 - Installable as a shared library.
 - meson build system
   (& make build system for in-tree QEMU integration)

### Changed

 - Standalone project, removing any QEMU dependency.
 - License clarifications.

[unreleased]: https://gitlab.freedesktop.org/slirp/libslirp/compare/v4.2.0...master
[4.2.0]: https://gitlab.freedesktop.org/slirp/libslirp/compare/v4.1.0...v4.2.0
[4.1.0]: https://gitlab.freedesktop.org/slirp/libslirp/compare/v4.0.0...v4.1.0
[4.0.0]: https://gitlab.freedesktop.org/slirp/libslirp/commits/v4.0.0
