cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include)

SET(src_spdm_transport_pcidoe_lib
    libspdm_doe_common.c
    libspdm_doe_pcidoe.c
)

ADD_LIBRARY(spdm_transport_pcidoe_lib STATIC ${src_spdm_transport_pcidoe_lib})
