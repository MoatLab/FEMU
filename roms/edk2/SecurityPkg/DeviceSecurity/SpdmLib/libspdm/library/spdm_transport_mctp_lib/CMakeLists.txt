cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include)

SET(src_spdm_transport_mctp_lib
    libspdm_mctp_common.c
    libspdm_mctp_mctp.c
)

ADD_LIBRARY(spdm_transport_mctp_lib STATIC ${src_spdm_transport_mctp_lib})
