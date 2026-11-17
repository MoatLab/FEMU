================================
SSI devices and SPI flash models
================================

QEMU's Synchronous Serial Interface (SSI) bus models the full-duplex transfer
of words between a controller and one selected peripheral. Most SPI flash
models, including ``m25p80``, are attached to controllers through this bus.

This page documents the expected boundary between a controller model and a
flash model for SPI fast-read dummy cycles. The boundary is important because
many real controllers expose dummy-cycle configuration in registers, while the
flash model observes only the byte stream delivered through ``ssi_transfer()``.

SSI transfer granularity
------------------------

``ssi_transfer()`` transfers one SSI word. Flash models that implement common
SPI NOR command streams usually consume one 8-bit word at a time:

* command opcode;
* address bytes;
* optional mode or continuous-read bytes;
* dummy bytes;
* data bytes.

The SSI core does not model individual clock edges or the number of active SPI
data lines. If a real transaction has a dummy phase expressed in clock cycles,
the device model that generates transfers on the SSI bus must represent that
phase as a number of dummy byte transfers.

Flash model responsibilities
----------------------------

A SPI flash model owns the command semantics for the flash device:

* which opcodes are recognized;
* how many address bytes are required;
* whether a command has mode bytes;
* how many dummy bytes must be consumed before data can be returned;
* manufacturer-specific differences in fast-read command behavior.

For the ``m25p80`` model, ``needed_bytes`` is a byte count. It must not store
raw dummy cycles. When a flash datasheet describes the dummy phase in cycles,
the flash model converts the cycles to bytes using the bus width used for the
dummy phase::

    dummy_bytes = DIV_ROUND_UP(dummy_cycles * dummy_bus_width, 8)

For SPI NOR fast-read commands modeled by ``m25p80``, the dummy phase follows
the address phase width. For example, output-only dual and quad read commands
such as DOR and QOR use one line for command, address, and dummy phases, then
use two or four lines only for the data phase. Dual I/O and Quad I/O commands
such as DIOR and QIOR use the wider bus for both address and dummy phases.

If the exact dummy phase cannot be represented as a whole number of SSI byte
transfers, the model should round up and log the limitation instead of silently
treating cycles as bytes.

Controller model responsibilities
---------------------------------

A controller model owns the behavior of the controller hardware:

* how guest-visible registers select command, address width, bus width, and
  dummy-cycle count;
* whether the guest supplies dummy bytes in a transmit FIFO;
* whether the controller itself generates the dummy phase for a memory-mapped,
  direct-read, or other automatic transfer mode;
* how chip-select state changes around controller-generated transfers.

When guest software writes dummy bytes into a transmit FIFO or manual transfer
path, the controller should pass those bytes to ``ssi_transfer()`` like any
other guest-provided byte. It should not add more dummy transfers on behalf of
the flash.

When hardware registers instruct the controller to generate a dummy phase, the
controller must emit dummy byte transfers before data transfers reach the flash
model. The controller should convert the configured cycle count using the bus
width that the controller uses during the dummy phase. For example:

* 8 dummy cycles on a single data line become 1 dummy byte;
* 8 dummy cycles on two data lines become 2 dummy bytes;
* 8 dummy cycles on four data lines become 4 dummy bytes.

The controller should not duplicate flash-specific opcode tables merely to
guess which commands need dummy cycles. In automatic modes the controller
already has enough hardware configuration to know whether it must generate a
dummy phase. In manual modes the guest-provided byte stream is authoritative.

Avoiding double counting
------------------------

Exactly one side should generate each dummy byte transfer seen by the flash:

* If the guest sends dummy bytes through the controller, the controller forwards
  them and the flash consumes them.
* If the guest programs a controller dummy-cycle register, the controller
  converts those cycles to dummy byte transfers and the flash consumes them.
* The flash may know that a command requires dummy bytes, but it does not create
  transfers on the SSI bus.

Do not implement controller-side snooping that watches manual-mode opcode
streams and injects extra dummy transfers based on flash opcodes. That mixes
flash command semantics into the controller and is fragile when flash models
gain correct dummy-byte accounting.

Examples in the tree
--------------------

The following models illustrate the boundary:

* ``hw/block/m25p80.c`` keeps fast-read dummy requirements as byte counts in
  ``needed_bytes``. Manufacturer-specific helpers convert datasheet dummy
  cycles to the byte stream expected by the model.
* ``hw/ssi/aspeed_smc.c`` generates dummy byte transfers for direct fast-read
  mode from controller registers, but manual user-mode writes are forwarded as
  guest-provided bytes.
* ``hw/ssi/npcm7xx_fiu.c`` converts the direct-read dummy configuration to the
  number of dummy byte transfers sent before reading data.

Review checklist
----------------

When adding or changing a SPI flash controller or flash model, check:

* Are dummy counts stored in byte units when they drive flash state machines?
* If a hardware register stores cycles, is the conversion to bytes based on the
  bus width of the dummy phase?
* Are manual guest-provided dummy bytes forwarded without extra injection?
* Are automatic controller-generated dummy phases modeled by the controller?
* Is flash-specific opcode knowledge kept in the flash model rather than copied
  into controller snooping paths?
