cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/os_stub/spdm_cert_verify_callback_sample
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/os_stub
)

SET(src_spdm_cert_verify_callback_sample
    spdm_cert_verify_callback.c
)

if ((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    ADD_COMPILE_OPTIONS(-DLIBSPDM_CPU_ARM)
endif()

ADD_LIBRARY(spdm_cert_verify_callback_sample STATIC ${src_spdm_cert_verify_callback_sample})
