#!/bin/bash

# this script will run one program one time, with a known good seed, to ensure it can pass the flow without any exception.

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
test_spdm_requester_vendor_cmds
test_spdm_responder_vendor_cmds
)

flag=0
fail_list=()
for ((i=0;i<${#cmds[*]};i++))
do
    echo ++++++++++ ${cmds[$i]} starting ++++++++++
    echo ./${cmds[$i]} ./seeds/${cmds[$i]}/*.raw
    ./${cmds[$i]} ./seeds/${cmds[$i]}/*.raw
    if [ $? -eq 0 ]; then
        echo ++++++++++ ${cmds[$i]} success  ++++++++++
    else
        echo ++++++++++ ${cmds[$i]} failing  ++++++++++
        flag=1
        fail_list[${#fail_list[*]}]=${cmds[$i]}
    fi
done

if [ ${flag} -eq 1 ]; then
    echo The summary of fail test is as following:
    for ((i=0;i<${#fail_list[*]};i++))
    do
        echo ${fail_list[$i]}
    done
fi
exit $flag