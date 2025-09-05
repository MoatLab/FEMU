cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/include/hal
                    ${LIBSPDM_DIR}/os_stub/rnglib
)

set (src_rnglib "")

if(TOOLCHAIN STREQUAL "ARM_GNU_BARE_METAL" OR TOOLCHAIN STREQUAL "RISCV_NONE")
    # The target must provide the required implementation at link time.
elseif(CMAKE_SYSTEM_NAME MATCHES "Linux" AND NOT TOOLCHAIN STREQUAL "ARM_DS2022")
SET(src_rnglib
    rng_linux.c
)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
SET(src_rnglib
    rng_win.c
)
else()
SET(src_rnglib
    rng_arm_sample.c
)
endif()

if (NOT src_rnglib STREQUAL "")
    ADD_LIBRARY(rnglib STATIC ${src_rnglib})
else ()
    message(WARNING "An rnglib implementation must be provided at link time")
endif()
