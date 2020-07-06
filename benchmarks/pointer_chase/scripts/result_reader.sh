# Simple List script to list all times captured in a run

if [[ "$#" -ne 1 ]]; then
	echo "Usage: ./result_reader.sh [foldername] "
	echo "foldername is the name of the folder that was generated with master_workload_generator.sh"
	exit 1
fi

foldername=$1

cat $foldername/*/*_time
