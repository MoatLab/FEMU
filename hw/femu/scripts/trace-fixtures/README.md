# Trace fixtures

Small synthetic traces for the self-test of `femu-trace-import.py`. Each
file has the column layout of one public trace set, with values written
by hand. None of them holds data from a real trace.

| File | Layout |
| --- | --- |
| `msr.csv` | MSR Cambridge (SNIA IOTTA), two volumes |
| `alibaba.csv` | Alibaba block traces 2020, two volumes |
| `alibaba-sizes.csv` | Alibaba `device_size.csv` |
| `tencent.csv` | Tencent CBS (SNIA IOTTA), two volumes |
| `cachelib.csv` | Meta CacheLib key-value cache trace, 202401 columns |
| `cachelib-202206.csv` | Meta CacheLib key-value cache trace, 202206 columns (no time) |
