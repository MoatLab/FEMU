cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal)

SET(src_rnglib_null
    rnglib.c
)

ADD_LIBRARY(rnglib_null STATIC ${src_rnglib_null})
