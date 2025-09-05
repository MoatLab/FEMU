#!/bin/bash

# Before run this script, please Download and install AFLplusplus. Unzip and follow docs\QuickStartGuide.txt. Build it with make.
# If command 'screen' not found, please install with: sudo apt install screen.
# If you also want to collect Code Coverage in Linux with AFLplusplus and lcov, please Install lcov with: sudo apt-get install lcov.

if [ "$#" -ne "3" ];then
    echo "Usage: $0 <CRYPTO> <GCOV> <duration>"
    echo "<CRYPTO> means selected Crypto library: mbedtls or openssl"
    echo "<GCOV> means enable Code Coverage or not: ON or OFF"
    echo "<duration> means the duration of every program keep fuzzing: NUMBER seconds"
    #read -p "press enter to exit"
    exit
fi

if [[ $1 = "mbedtls" || $1 = "openssl" ]]; then
    echo "<CRYPTO> parameter is $1"
else
    echo "Usage: $0 <CRYPTO> <GCOV> <duration>"
    echo "<CRYPTO> means selected Crypto library: mbedtls or openssl"
    echo "<GCOV> means enable Code Coverage or not: ON or OFF"
    echo "<duration> means the duration of every program keep fuzzing: NUMBER seconds"
    exit
fi

if [[ $2 = "ON" || $2 = "OFF" ]]; then    
    echo "<GCOV> parameter is $2"
else
    echo "Usage: $0 <CRYPTO> <GCOV> <duration>"
    echo "<CRYPTO> means selected Crypto library: mbedtls or openssl"
    echo "<GCOV> means enable Code Coverage or not: ON or OFF"
    echo "<duration> means the duration of every program keep fuzzing: NUMBER seconds"
    exit
fi

echo "<duration> parameter is $3"
export duration=$3

echo "start fuzzing in Linux with AFLplusplus"     

pkill screen

export script_path="$(cd "$(dirname $0)";pwd)"
export libspdm_path=$script_path/../..
export fuzzing_path=$libspdm_path/unit_test/fuzzing
export fuzzing_seeds=$libspdm_path/unit_test/fuzzing/seeds
export TIMESTAMP=`date +%Y-%m-%d_%H-%M-%S`

# Here '~/afl-2.52b/' is the AFL PATH, replace it with yours.

export AFL_PATH=~/AFLplusplus/
export PATH=$PATH:$AFL_PATH


# afl-plusplus-fuzz -i testcase_dir -o /dev/shm/findings_dir ./build/bin/test_spdm_responder_version @@

# afl-plusplus-fuzz -i ./testcase_dir -o /dev/shm/findings_dir ./build/bin/test_spdm_responder_version @@

# afl-fuzz -i $HOME/fuzzing_xpdf/pdf_examples/ -o $HOME/fuzzing_xpdf/out/ -s 123 -- $HOME/fuzzing_xpdf/install/bin/pdftotext @@ $HOME/fuzzing_xpdf/output

if [[ $PWD!=$libspdm_path ]];then
    pushd $libspdm_path
    latest_hash=`git log --pretty="%h" -1`
    export fuzzing_out=$libspdm_path/unit_test/fuzzing/out_$1_$latest_hash-$TIMESTAMP
    export build_fuzzing=$libspdm_path/build_fuzz_$1_$latest_hash-$TIMESTAMP
fi

if [ ! -d "$fuzzing_out" ];then
    mkdir $fuzzing_out
fi

for i in $fuzzing_out/*;do
    if [[ ! -d $i/crashes ]] && [[ ! -d $i/hangs ]];then
        continue
    fi

    if [[ "`ls -A $i/crashes`" != "" ]];then
        echo -e "\033[31m There are some crashes \033[0m"
        echo -e "\033[31m Path in $i/crashes \033[0m"
        exit
    fi

    if [[ "`ls -A $i/hangs`" != "" ]];then
        echo -e "\033[31m There are some hangs \033[0m"
        echo -e "\033[31m Path in $i/hangs \033[0m"
        exit
    fi
done

rm -rf $fuzzing_out/*

if [[ "core" != `cat /proc/sys/kernel/core_pattern` ]];then
    # Here 'test' is the sudo password, replace it with yours.
    echo 'test' | sudo -S bash -c 'echo core >/proc/sys/kernel/core_pattern'
    pushd /sys/devices/system/cpu/
    echo 'test' | sudo -S bash -c 'echo performance | tee cpu*/cpufreq/scaling_governor'
    popd
fi

if [ -d "$build_fuzzing" ];then
    rm -rf $build_fuzzing
fi

mkdir $build_fuzzing
pushd $build_fuzzing

cmake -DARCH=x64 -DTOOLCHAIN=AFL -DTARGET=Release -DCRYPTO=$1 -DGCOV=$2 ..
make copy_sample_key
make
pushd bin

cmds=(
test_spdm_transport_mctp_encode_message
test_spdm_transport_mctp_decode_message
test_spdm_transport_pci_doe_encode_message
test_spdm_transport_pci_doe_decode_message
test_spdm_decode_secured_message
test_spdm_encode_secured_message
test_spdm_requester_encap_digests
test_spdm_requester_encap_certificate
test_spdm_requester_encap_challenge_auth
test_spdm_requester_encap_key_update
test_spdm_requester_encap_request
test_spdm_requester_get_version
test_spdm_requester_get_capabilities
test_spdm_requester_negotiate_algorithms
test_spdm_requester_get_digests
test_spdm_requester_get_certificate
test_spdm_requester_challenge
test_spdm_requester_get_measurements
test_spdm_requester_key_exchange
test_spdm_requester_finish
test_spdm_requester_psk_exchange
test_spdm_requester_psk_finish
test_spdm_requester_heartbeat
test_spdm_requester_key_update
test_spdm_requester_end_session
test_spdm_responder_encap_challenge
test_spdm_responder_encap_get_certificate
test_spdm_responder_encap_get_digests
test_spdm_responder_encap_key_update
test_spdm_responder_encap_response
test_spdm_responder_version
test_spdm_responder_capabilities
test_spdm_responder_algorithms
test_spdm_responder_digests
test_spdm_responder_certificate
test_spdm_responder_challenge_auth
test_spdm_responder_measurements
test_spdm_responder_key_exchange
test_spdm_responder_finish_rsp
test_spdm_responder_psk_exchange_rsp
test_spdm_responder_psk_finish_rsp
test_spdm_responder_heartbeat_ack
test_spdm_responder_key_update
test_spdm_responder_end_session
test_spdm_responder_if_ready
test_x509_certificate_check
test_spdm_responder_set_certificate
test_spdm_requester_set_certificate
test_spdm_responder_csr
test_spdm_requester_get_csr
test_spdm_responder_chunk_get
test_spdm_requester_chunk_get
test_spdm_responder_chunk_send_ack
test_spdm_requester_chunk_send
test_spdm_responder_supported_event_types
test_spdm_requester_get_event_types
test_spdm_requester_vendor_cmds
test_spdm_responder_vendor_cmds
)

export FUZZ_START_TIME=`date +%Y-%m-%d_%H:%M:%S`

for ((i=0;i<${#cmds[*]};i++))
do
    echo ${cmds[$i]}
    screen -ls | grep ${cmds[$i]}
    if [[ $? -ne 0 ]]
    then
    screen -dmS ${cmds[$i]}
    fi
    screen -S ${cmds[$i]} -p 0 -X stuff "afl-plusplus-fuzz -i $fuzzing_seeds/${cmds[$i]} -o $fuzzing_out/${cmds[$i]} ./${cmds[$i]} @@"
    screen -S ${cmds[$i]} -p 0 -X stuff $'\n'
    sleep $duration
    screen -S ${cmds[$i]} -X quit
    sleep 5
done

if [[ $2 = "ON" ]]; then
    cd $fuzzing_out
    mkdir coverage_log
    cd coverage_log
    lcov --capture --directory $build_fuzzing --output-file coverage.info
    genhtml coverage.info --output-directory . --title "Started at : $FUZZ_START_TIME | Crypto lib : $1 | AFL Plusplus Fuzzing | Duration : $duration secs per testcase"
fi

function walk_dir(){
    for file in `ls $1`
    do
        if [[ -d $1"/"$file ]]
        then
            walk_dir $1"/"$file
        elif [[ $file = "fuzzer_stats" ]]
        then
            echo $1"/"$file
            unique_crashes=''
            unique_hangs=''
            afl_banner=''
            while read line
                do
                    if [[ $line =~ "unique_crashes" ]]
                    then
                        unique_crashes=${line##*:}
                    elif [[ $line =~ "unique_hangs" ]]
                    then
                        unique_hangs=${line##*:}
                    elif [[ $line =~ "afl_banner" ]]
                    then
                        afl_banner=${line##*:}
                    fi
                done < $1"/"$file
            echo $afl_banner,$unique_crashes,$unique_hangs >> $fuzzing_out"/SummaryList.csv"
        fi
    done
}

echo afl_banner,unique_crashes,unique_hangs > $fuzzing_out"/SummaryList.csv"
walk_dir $fuzzing_out