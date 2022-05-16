# Virtual Boot ROM for NPCM7xx SoCs

This is not an officially supported Google product.

This is a super simple Boot ROM that is intended to be used as a `-bios` image
for [QEMU](http://www.qemu.org/) when emulating an NPCM7xx-based machine.

## Building

If you have a 32-bit ARM compiler installed as `arm-none-eabi-gcc`, simply run
`make`.

If your ARM compiler has a different name, you'll need to override the
`CROSS_COMPILE` prefix, e.g. like this:

```
make CROSS_COMPILE=arm-linux-gnueabi-
```

If either case is successful, a `npcm7xx_bootrom.bin` file will be produced.

## Using

The Boot ROM image may be passed to a QEMU system emulator using the `-bios` option. For example like this:

```
qemu-system-arm -machine quanta-gsj -nographic \
    -bios "${IMAGES}/npcm7xx_bootrom.bin"
    -drive file="${IMAGES}/image-bmc,if=mtd,bus=0,unit=0,format=raw,snapshot=on"
```

## Limitations

*   Secure boot is not supported.
*   Only booting from offset 0 of the flash at SPI0 CS0 is implemented.
*   Fallback images (if the first image doesn't boot) are not implemented.
*   Exception vectors are copied to SRAM, but not remapped.
*   Most OTP bits and straps are not honored.
*   The reset type bits are not updated.
*   OTP protection is not implemented.
*   No clock initialization is performed.
*   UART programming protocol is not implemented.
*   Host notification through the PCI mailbox is not implemented.
*   Most fields in the ROM status structure are not set.
