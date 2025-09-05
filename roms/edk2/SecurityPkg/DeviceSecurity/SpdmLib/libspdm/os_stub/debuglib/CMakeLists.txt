cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal)

SET(src_debuglib
    debuglib.c
)

ADD_LIBRARY(debuglib STATIC ${src_debuglib})
