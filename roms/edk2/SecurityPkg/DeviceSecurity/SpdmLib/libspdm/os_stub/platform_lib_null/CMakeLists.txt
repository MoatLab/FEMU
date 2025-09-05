cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
SET(src_platform_lib_null
    time_linux.c
    watchdog.c
)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
SET(src_platform_lib_null
    time_win.c
    watchdog.c
)
endif()

ADD_LIBRARY(platform_lib_null STATIC ${src_platform_lib_null})
