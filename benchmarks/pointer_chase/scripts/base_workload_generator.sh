# This script generates a number of child scripts that vary two parameters:

# ---- OPS - Number of Operations i.e. number of lists that need to be accessed.

# ---- Pointer List Length - Number of elements in a Linked List.


if [[ "$#" -ne 1 ]]; then
	echo "Usage ./base_workload_generator [1,2]"
	echo "1. Varies Operations"
	echo "2. Varies Linked List Length"
	exit
fi

CONFIG=$1
SRC_DIR=../../..
DEV=/dev/nvme0n1
DISK_SIZE_GB=10


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

for OPS in "${opsList[@]}"; 
do
	for POINTERLENGTH in "${ptrList[@]}";
	do
		echo "POINTERLENGTH = $POINTERLENGTH OPS = $OPS"
		workload_dir=$base_dir/wl_${OPS}_$POINTERLENGTH
		mkdir -p $workload_dir;
		script_file=$workload_dir/run.sh
		echo "$SRC_DIR/pointer_generator $OPS $MAX_DISK_BLOCKS $POINTERLENGTH $POINTERLENGTH" >> $script_file
		echo "$SRC_DIR/write_pointer_to_disk $DEV" >> $script_file
		echo "echo \"If computation_mode=0, run: $SRC_DIR/host_pointer_reader $DEV\"" >> $script_file
		echo "echo \"If computation_mode=1, run: $SRC_DIR/nsc_pointer_reader $DEV\"" >> $script_file
		chmod +x $script_file
	done
done

