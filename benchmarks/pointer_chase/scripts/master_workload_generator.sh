# This script generates a number of child scripts that vary two parameters:

# ---- OPS - Number of Operations i.e. number of lists that need to be accessed.
# ---- Pointer List Length - Number of elements in a Linked List.

# The script can be configured to only generate workloads (to be run later)
# or it can be used both for generating and running the pointer chase operation.

if [[ "$#" -ne 1 ]]; then
	echo "Usage ./base_workload_generator [1,2]"
	echo "1. Varies Operations"
	echo "2. Varies Linked List Length"
	exit
fi

# configuration could be vary ops or pointerlist
CONFIG=$1
# location of all source binaries
SRC_DIR=../../..
BASE_DIR=`pwd`
# device
DEV=/dev/nvme0n1
# device size for which pointer should be generated
DISK_SIZE_GB=10
# generate disk pointer files hp.dat and dp.dat when benchmark runs.
# 0 does not generate the files and writes command to generate in run.sh
# 1 generates the files
GENERATE_DISK_POINTERS=1
# write disk pointers to disk
# writes pointers generated to the underlying device.
# 0 does not write pointers in dp.dat to the device, but writes the command in run.sh
# 1 writes the pointers in dp.dat on disk
WRITE_DISK_POINTERS=1
# host or nsg configuration, 0 for host, 1 for nsc
# appropriate command is written to run.sh
HOST_OR_NSC=0
# execute pointer chase
# runs host or nsc command on disk
POINTER_EXEC=0

BLOCK_SIZE_BYTES=4096
MAX_DISK_BLOCKS=`echo "$DISK_SIZE_GB * 1024 * 1024 * 1024 / $BLOCK_SIZE_BYTES" | bc`

echo "MAX DISK BLOCKS $MAX_DISK_BLOCKS"

# vary number of operations

opsWorkloadList=(1024 10240 51200)
listLengthWorkloadList=(10240)

# vary pointer length

opsPointerSizeList=(5)
listLengthPointerSizeList=(1 2 3 4 5 6 7 8)

if [[ "$CONFIG" -eq 1 ]]; then
	opsList=( "${opsWorkloadList[@]}" )
	ptrList=( "${opsPointerSizeList[@]}" )
	base_dir=ops
	rm -rf ops
else
	opsList=( "${listLengthWorkloadList[@]}" )
	ptrList=( "${listLengthPointerSizeList[@]}" )
	base_dir=pointerSize
	rm -rf pointerSize
fi

echo "RUN WITH OPS $opsList PTRSIZE $ptrList"

if [[ "$POINTER_EXEC" -ne 0 ]]; then
	echo "Please set host CPU using"
	echo "cpulimit -c CPU_LIMIT -p pid"
	read
fi

for OPS in "${opsList[@]}"; 
do
	for POINTERLENGTH in "${ptrList[@]}";
	do
		echo "POINTERLENGTH = $POINTERLENGTH OPS = $OPS"
		workload_dir=$base_dir/wl_${OPS}_$POINTERLENGTH
		mkdir -p $workload_dir;
		script_file=$workload_dir/run.sh

		echo "$SRC_DIR/pointer_generator $OPS $MAX_DISK_BLOCKS $POINTERLENGTH $POINTERLENGTH" >> $script_file
		if [[ "$GENERATE_DISK_POINTERS" -eq 1 ]]; then
			cd $workload_dir && \
			$SRC_DIR/pointer_generator $OPS $MAX_DISK_BLOCKS $POINTERLENGTH $POINTERLENGTH && \
			cd $BASE_DIR
		fi

		echo "$SRC_DIR/write_pointer_to_disk $DEV" >> $script_file
		if [[ "$WRITE_DISK_POINTERS" -eq 1 ]]; then
			cd $workload_dir && \
			sudo $SRC_DIR/write_pointer_to_disk $DEV && \
			cd $BASE_DIR
		fi

		if [[ "$HOST_OR_NSC" -eq 0 ]]; then
			echo "echo \"If computation_mode=0, run (using sudo): $SRC_DIR/host_pointer_reader $DEV > host_time\"" >> $script_file
			if [[ "$POINTER_EXEC" -eq 1 ]]; then
				cd $workload_dir && \
				sudo $SRC_DIR/host_pointer_reader $DEV > host_time && \
				cd $BASE_DIR
			fi
		elif [[ "$HOST_OR_NSC" -eq 1 ]]; then
			echo "echo \"If computation_mode=1, run (using sudo): $SRC_DIR/nsc_pointer_reader $DEV > nsc_time\"" >> $script_file
			if [[ "$POINTER_EXEC" -eq 1 ]]; then
				cd $workload_dir && \
				sudo $SRC_DIR/nsc_pointer_reader $DEV > nsc_time && \
				cd $BASE_DIR
			fi
		fi
		chmod +x $script_file
	done
done
