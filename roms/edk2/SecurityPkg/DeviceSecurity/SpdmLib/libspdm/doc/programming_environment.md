# Programming Environment

## Core Libraries

The core libraries in `libspdm/library` adhere to the C99 standard and make use of the following
freestanding headers.
- stdint.h
- stdbool.h
- stdef.h

If a compiler does not provide at least one of these headers or if at least one of the compiler's
headers must be overridden by the Integrator's headers then they can be overridden with the
`LIBSPDM_STDINT_ALT`, `LIBSPDM_STDBOOL_ALT`, or `LIBSPDM_STDDEF_ALT` macros. The inclusion of only
freestanding headers indicates that the core libraries are suitable for embedded and systems
programming. Any functionality beyond the freestanding headers is indicated through the
`libspdm/include/hal/library` headers and is provided by either `libspdm/os_stub` or by the
library's Integrator. All statically allocated memory is read-only and the core libraries do not
dynamically allocate memory.

### Core Library Assumptions

libspdm has the following assumptions against the compiler, target hardware architecture, and target
operating environment.
- The endianness of the target architecture is little-endian.
- The target architecture is a 32-bit or 64-bit system.
- The compiler supports the `#pragma pack()` directive.
- If a pointer has been `memset` to a value of `0` then the pointer is equal to `NULL`.
- Characters are encoded as ASCII so that, for example, `('A' == 65)` evaluates to `1`.

## Assertion Philosophy

The `LIBSPDM_ASSERT` macro is used to document assumptions within the codebase and within an SPDM
endpoint. If a `LIBSPDM_ASSERT` check fails then it is due to any combination of
- a bug in the libspdm codebase.
- misuse of libspdm's public API by the Integrator.
- misconfiguration of the SPDM endpoint by the Integrator.

A `LIBSPDM_ASSERT` check should never fail due to an SPDM message received from a peer endpoint.
Assertions can be removed during compilation to reduce the size of object files. If
`LIBSPDM_CHECK_MACRO` is set then libspdm will check configuration macros, provided by the
Integrator, during compilation.
