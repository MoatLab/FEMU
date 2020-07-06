This script is run from guest, please copy entire `../pointer_chase` folder to the guest.

This folder contains scripts to measure pointer chase benchmarks. 
Each operation is run assuming a 100G disk containing 2560K x 4K blocks (= 10GB)
This parameter (2621440) is used in ./pointer\_generator script <max_pointer_value>

`master_workload_generator.sh` generates bechmarks for three different configurations
for both `host` and `nsc` mode:

1. Vary number of Pointer chase operations. 1K, 10K, 100K, 1M.
	This can be done varying the `num_lists` parameter.
	We keep pointer size limited to 3 (set `min_list_length` and `max_list_length`)
	We keep CPU utilization of Host CPU at 50% and device at 100%

2. Vary the length of each Pointer list from 1 to 10.
	This can be done setting `min_list_length` and `max_list_length` to 1-10.
	We keep the `num_lists` parameter constant at 100K.
	We keep CPU utilization of Host CPU at 50% and device at 100%

3. Vary the CPU usage of the host CPU from 10-100%.
	This is done using cpulimit.
	We keep the `num_lists` parameter constant at 100K.
	We keep the `min_list_length` and `max_list_length` set to 3.

