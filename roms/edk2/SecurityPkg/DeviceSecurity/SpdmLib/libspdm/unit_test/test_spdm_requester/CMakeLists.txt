cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/unit_test/test_spdm_requester
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/unit_test/include
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
                    ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common
                    ${LIBSPDM_DIR}/os_stub
)

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        ADD_COMPILE_OPTIONS(/wd4819)
    endif()
endif()

SET(src_test_spdm_requester
    test_spdm_requester.c
    get_version.c
    get_capabilities.c
    negotiate_algorithms.c
    get_digests.c
    get_certificate.c
    challenge.c
    get_event_types.c
    get_measurements.c
    key_exchange.c
    finish.c
    psk_exchange.c
    psk_finish.c
    heartbeat.c
    key_update.c
    end_session.c
    encap_certificate.c
    encap_challenge_auth.c
    encap_digests.c
    encap_key_update.c
    encap_request.c
    set_certificate.c
    get_csr.c
    chunk_get.c
    chunk_send.c
    vendor_request.c
    error_test/get_version_err.c
    error_test/get_capabilities_err.c
    error_test/negotiate_algorithms_err.c
    error_test/get_digests_err.c
    error_test/key_exchange_err.c
    error_test/get_measurements_err.c
    error_test/get_event_types_err.c
    error_test/vendor_request_err.c
    ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/common.c
    ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/algo.c
    ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/support.c
)

SET(test_spdm_requester_LIBRARY
    memlib
    debuglib
    spdm_responder_lib
    spdm_requester_lib
    spdm_common_lib
    ${CRYPTO_LIB_PATHS}
    rnglib
    cryptlib_${CRYPTO}
    malloclib
    spdm_crypt_lib
    spdm_crypt_ext_lib
    spdm_secured_message_lib
    spdm_device_secret_lib_sample
    spdm_transport_test_lib
    cmockalib
    platform_lib
)

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    SET(test_spdm_requester_LIBRARY ${test_spdm_requester_LIBRARY} armbuild_lib)
endif()

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(test_spdm_requester
                   ${src_test_spdm_requester}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib>
                   $<TARGET_OBJECTS:spdm_requester_lib>
                   $<TARGET_OBJECTS:spdm_common_lib>
                   $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
                   $<TARGET_OBJECTS:rnglib>
                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
                   $<TARGET_OBJECTS:malloclib>
                   $<TARGET_OBJECTS:spdm_crypt_lib>
                   $<TARGET_OBJECTS:spdm_secured_message_lib>
                   $<TARGET_OBJECTS:spdm_device_secret_lib_sample>
                   $<TARGET_OBJECTS:spdm_transport_test_lib>
                   $<TARGET_OBJECTS:cmockalib>
                   $<TARGET_OBJECTS:platform_lib>
    )
else()
    ADD_EXECUTABLE(test_spdm_requester ${src_test_spdm_requester})
    TARGET_LINK_LIBRARIES(test_spdm_requester ${test_spdm_requester_LIBRARY})
endif()


