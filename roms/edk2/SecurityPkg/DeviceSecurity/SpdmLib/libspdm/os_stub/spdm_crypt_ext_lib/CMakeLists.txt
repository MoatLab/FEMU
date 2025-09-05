cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/os_stub
)

SET(src_spdm_crypt_ext_lib
    spdm_crypt_ext.c
)

ADD_LIBRARY(spdm_crypt_ext_lib STATIC ${src_spdm_crypt_ext_lib})
