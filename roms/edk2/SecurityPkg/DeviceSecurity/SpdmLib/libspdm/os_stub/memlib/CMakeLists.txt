cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal)

SET(src_memlib
    compare_mem.c
    copy_mem.c
    set_mem.c
    zero_mem.c
)

ADD_LIBRARY(memlib STATIC ${src_memlib})
