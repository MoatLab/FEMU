cmake_minimum_required(VERSION 2.8.12)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    ADD_COMPILE_OPTIONS(${CMOCKA_FLAGS} -DHAVE_SIGNAL_H)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    ADD_COMPILE_OPTIONS(${CMOCKA_FLAGS} -DHAVE_VSNPRINTF -DHAVE_SNPRINTF)
    if((TOOLCHAIN STREQUAL "VS2015") OR (TOOLCHAIN STREQUAL "VS2019") OR (TOOLCHAIN STREQUAL "VS2022"))
        ADD_COMPILE_OPTIONS(/wd4819)
    endif()
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/unit_test/cmockalib
                    ${LIBSPDM_DIR}/include
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include
                    ${LIBSPDM_DIR}/unit_test/cmockalib/cmocka/include/cmockery
)

if(TOOLCHAIN STREQUAL "ARM_DS2022")
    SET(src_CmockaLib
        cmocka/src/cmocka.c
        strdup.c
    )
else()
    SET(src_CmockaLib
        cmocka/src/cmocka.c
    )
endif()

ADD_LIBRARY(cmockalib STATIC ${src_CmockaLib})
