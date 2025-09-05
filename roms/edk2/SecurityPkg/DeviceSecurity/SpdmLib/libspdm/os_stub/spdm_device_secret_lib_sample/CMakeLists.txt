cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/os_stub/spdm_device_secret_lib_sample
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/os_stub
)

SET(src_spdm_device_secret_lib_sample
    lib.c
    cert.c
)

if ((ARCH STREQUAL "arm") OR (ARCH STREQUAL "aarch64"))
    ADD_COMPILE_OPTIONS(-DLIBSPDM_CPU_ARM)
endif()

ADD_LIBRARY(spdm_device_secret_lib_sample STATIC ${src_spdm_device_secret_lib_sample})
