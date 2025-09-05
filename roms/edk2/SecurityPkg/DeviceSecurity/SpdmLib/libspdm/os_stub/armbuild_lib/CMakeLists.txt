cmake_minimum_required(VERSION 2.8.12)

SET(src_armbuild_lib
    div64.c
)

ADD_LIBRARY(armbuild_lib STATIC ${src_armbuild_lib})
