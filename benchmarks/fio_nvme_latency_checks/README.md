This folder contains generic benchmarking scripts for tuning FEMU to real NVMe SSD being accessed by guest.

We check for random/sequential writes and random/sequential reads made from the guest on both the nvme device and the FEMU emulated nvme device.

There are two levels of latencies:

1. `flash_read_latency` and `flash_write_latency` are the latencies imposed in the flash layer. 
	These can be configured during runtime in `run-blackbox.sh`. The flash latencies default to `0`
2.  `PCIe_READ_LATENCY` and `PCIe_PROG_LATENCY` are macros defined in `hw/block/femu/ftl/ftl.h` that can 
	be used to set latency incurred during the return path. Currently, they are set to 2 micro seconds.
