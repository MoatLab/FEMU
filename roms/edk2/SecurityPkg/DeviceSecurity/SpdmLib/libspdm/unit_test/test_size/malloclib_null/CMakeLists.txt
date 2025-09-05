cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include)

SET(src_malloclib_null
    malloclib.c
)

ADD_LIBRARY(malloclib_null STATIC ${src_malloclib_null})
