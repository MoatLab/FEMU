## Environment variables

FEMU reads these variables from the environment of the QEMU process. They are
debugging and host-placement aids, not device configuration, so they have no
`-device` property. When QEMU runs under `sudo`, pass them through, for example
`sudo FEMU_EXP_LOG=1 ./run-blackbox.sh` or `sudo -E`.

| Variable | Read by | Effect |
| --- | --- | --- |
| `FEMU_MBE_INTERLEAVE` | memory backend, every mode (`hw/femu/backend/dram.c`) | `on` interleaves the backend memory across NUMA nodes 0 and 1; `0` or `1` binds it to that node. Other values are ignored with a message. Unset leaves the host default policy. |
| `FEMU_FDP_DEBUG` | bbssd FTL (`hw/femu/bbssd/ftl.c`) | Any value, even empty, prints FDP placement and reclaim traces to stderr. |
| `FEMU_EXP_LOG` | bbssd FTL (`hw/femu/bbssd/ftl-exp.c`) | A non-empty value prints `[EXP]` lines to stderr that trace the writes, overwrites, deallocations, garbage collection moves and erases of pages whose data contains `FEMU_SECRET`; without `FEMU_SECRET` nothing is traced. |
| `FEMU_SECRET` | bbssd FTL (`hw/femu/bbssd/ftl-exp.c`) | A non-empty marker string that selects the pages `FEMU_EXP_LOG` traces. |
| `FEMU_DUMP_LPN` | bbssd FTL (`hw/femu/bbssd/ftl-exp.c`) | A logical page number (decimal or 0x hex) whose backend page is hex-dumped to stderr on every read not served from the write buffer, independent of `FEMU_EXP_LOG`. |
| `FEMU_KV_SELFTEST` | KV FTL (`hw/femu/kvssd/kvssd-ftl.c`) | Any value runs the KV FTL self-test once at realize and logs the result. |
