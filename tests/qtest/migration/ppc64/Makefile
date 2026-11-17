.PHONY: all clean
all: a-b-kernel.h

a-b-kernel.h: ppc64.kernel
	echo "$$__note" > $@
	xxd -i $< | sed -e '/.*int.*/d' >> $@

ppc64.kernel: ppc64.elf
	$(CROSS_PREFIX)objcopy -O binary -S $< $@

ppc64.elf: a-b-kernel.S
	$(CROSS_PREFIX)gcc -mbig-endian -static -o $@ -nostdlib -Wl,--build-id=none $<

clean:
	$(RM) *.kernel *.elf *.h
