cmake_minimum_required(VERSION 2.8.12)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    ADD_COMPILE_OPTIONS(-Wno-incompatible-pointer-types -Wno-pointer-sign)
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include

                    ${LIBSPDM_DIR}/os_stub/include
)

SET(src_cryptstublib_dummy
    rand_dummy.c
    timeclock_dummy.c
)

ADD_LIBRARY(cryptstublib_dummy STATIC ${src_cryptstublib_dummy})
