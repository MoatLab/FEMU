#!/bin/bash

# If command 'screen' not found, please install with: sudo apt install screen.

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

if [[ "core" != `cat /proc/sys/kernel/core_pattern` ]];then
    # Here 'test' is the sudo password, replace it with yours.
    echo 'test' | sudo -S bash -c 'echo core >/proc/sys/kernel/core_pattern'
    pushd /sys/devices/system/cpu/
    echo 'test' | sudo -S bash -c 'echo performance | tee cpu*/cpufreq/scaling_governor'
    popd
fi

echo "start fuzzing in Linux with OSS-Fuzz locally"

pkill screen

export script_path="$(cd "$(dirname $0)";pwd)"
export libspdm_path=$script_path/../..

cd $libspdm_path/..
rm -rf oss-fuzz
git clone https://github.com/google/oss-fuzz.git
cd oss-fuzz
export PROJECT_NAME=libspdm
export LANGUAGE=c
python3 infra/helper.py generate $PROJECT_NAME --language=$LANGUAGE
cp $script_path/oss-fuzz_conf/* ./projects/$PROJECT_NAME/
sed -i "s/-DCRYPTO=mbedtls/-DCRYPTO=$1/g" ./projects/$PROJECT_NAME/build.sh
sed -i "s/-DGCOV=ON/-DGCOV=$2/g" ./projects/$PROJECT_NAME/build.sh

python3 infra/helper.py build_image $PROJECT_NAME
if [[ $2 = "ON" ]]; then
    python3 infra/helper.py build_fuzzers --sanitizer coverage $PROJECT_NAME
else
    python3 infra/helper.py build_fuzzers --sanitizer address $PROJECT_NAME
fi

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
test_spdm_requester_vendor_cmds
test_spdm_responder_vendor_cmds
)

for ((i=0;i<${#cmds[*]};i++))
do
    echo ${cmds[$i]}
    mkdir -p ./build/corpus/$PROJECT_NAME/${cmds[$i]}
    zip -j ./build/out/$PROJECT_NAME/${cmds[$i]}_seed_corpus.zip $libspdm_path/unit_test/fuzzing/seeds/${cmds[$i]}/*
    screen -ls | grep ${cmds[$i]}
    if [[ $? -ne 0 ]]
    then
    screen -dmS ${cmds[$i]}
    fi
    screen -S ${cmds[$i]} -p 0 -X stuff "python3 infra/helper.py run_fuzzer --corpus-dir=./build/corpus/$PROJECT_NAME/${cmds[$i]} $PROJECT_NAME ${cmds[$i]}"
    screen -S ${cmds[$i]} -p 0 -X stuff $'\n'
    sleep $duration
    screen -S ${cmds[$i]} -X quit
    sleep 5
done

if [[ $2 = "ON" ]]; then
    python3 infra/helper.py coverage --no-corpus-download $PROJECT_NAME
fi
