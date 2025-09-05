# Virtual Boot ROM for AST27x0 SoCs

This is not an officially supported Google product.

This is a super simple Boot ROM that is intended to be used as a `-bios` image
for [QEMU](http://www.qemu.org/) when emulating an AST27x0-based machine.

## Building

If you have a 64-bit ARM compiler installed as `aarch64-linux-gnu-gcc`, simply run
`make`.

If your ARM compiler has a different name, you'll need to override the
`CROSS_COMPILE` prefix, e.g. like this:

```
make CROSS_COMPILE=aarch64-linux-gnueabi-
```

If either case is successful, a `ast27x0_bootrom.bin` file will be produced.

## Using

The Boot ROM image may be passed to a QEMU system emulator using the `-bios` option. For example like this:

```
qemu-system-aarch64 -machine ast2700a1-evb -nographic \
    -bios ${IMAGES}/ast27x0_bootrom.bin \
    -drive file=${IMAGES}/image-bmc,format=raw,if=mtd \
    -snapshot
```

## Limitations
