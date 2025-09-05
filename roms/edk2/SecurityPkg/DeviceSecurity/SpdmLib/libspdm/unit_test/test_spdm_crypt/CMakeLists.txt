cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/unit_test/include
                    ${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
                    ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common
                    ${LIBSPDM_DIR}/os_stub/include
                    ${LIBSPDM_DIR}/os_stub
)

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if((TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        ADD_COMPILE_OPTIONS(/wd4819)
    endif()
endif()

SET(src_test_spdm_crypt
    test_spdm_crypt.c
    ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/support.c
    ${LIBSPDM_DIR}/unit_test/spdm_unit_test_common/algo.c
)

SET(test_spdm_crypt_LIBRARY
    memlib
    debuglib
    spdm_crypt_lib
    ${CRYPTO_LIB_PATHS}
    cryptlib_${CRYPTO}
    rnglib
    malloclib
    cmockalib
    spdm_device_secret_lib_sample
    spdm_crypt_ext_lib
)

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    SET(test_spdm_crypt_LIBRARY ${test_spdm_crypt_LIBRARY} armbuild_lib)
endif()

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(test_spdm_crypt
                   ${src_test_spdm_crypt}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib>
                   $<TARGET_OBJECTS:spdm_crypt_lib>
                   $<TARGET_OBJECTS:${CRYPTO_LIB_PATHS}>
                   $<TARGET_OBJECTS:rnglib>
                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
                   $<TARGET_OBJECTS:malloclib>
    )
else()
    ADD_EXECUTABLE(test_spdm_crypt ${src_test_spdm_crypt})
    TARGET_LINK_LIBRARIES(test_spdm_crypt ${test_spdm_crypt_LIBRARY})
endif()


