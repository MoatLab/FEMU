cmake_minimum_required(VERSION 2.8.12)

if(TOOLCHAIN MATCHES "VS")
    SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /GL-")
endif()

if(TOOLCHAIN MATCHES "CLANG")
    ADD_COMPILE_OPTIONS(-Wno-incompatible-library-redeclaration)
endif()

INCLUDE_DIRECTORIES(${LIBSPDM_DIR}/include)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    if(TOOLCHAIN STREQUAL "RISCV_XPACK")
        SET(src_intrinsiclib
            compiler_stub.c
            memory_intrinsics.c
            ashldi3.c
        )
    else()
        SET(src_intrinsiclib
            compiler_stub.c
            memory_intrinsics.c
        )
    endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(ARCH STREQUAL "x64")
        SET(src_intrinsiclib
            compiler_stub.c
            memory_intrinsics.c
        )
    elseif(ARCH STREQUAL "ia32")
        SET(src_intrinsiclib
            compiler_stub.c
            memory_intrinsics.c
            ia32/math_div_s64x64.c
            ia32/math_div_s64x64_remainder.c
            ia32/math_div_u64x64.c
            ia32/math_div_u64x64_remainder.c
            ia32/math_ftol.c
            ia32/math_lshift_s64.c
            ia32/math_mult_s64x64.c
            ia32/math_remainder_s64x64.c
            ia32/math_remainder_u64x64.c
            ia32/math_rShift_s64.c
            ia32/math_rShift_u64.c
        )
    endif()
endif()

ADD_LIBRARY(intrinsiclib STATIC ${src_intrinsiclib})
