cmake_minimum_required(VERSION 3.28)
project(quickjs C)

set(QUICKJS_SOURCES
    quickjs.c
    quickjs.h
    quickjs-libc.c
    quickjs-libc.h
    libregexp.c
    libregexp.h
    libunicode.c
    libunicode.h
    cutils.c
    cutils.h
    dtoa.c
    dtoa.h
)

# Compiler flags
add_library(libquickjs STATIC ${QUICKJS_SOURCES})

target_compile_options(libquickjs PRIVATE
    -Wall
    -Wextra
    -Wno-sign-compare
    -Wno-missing-field-initializers
    -Wundef
    -Wuninitialized
    -Wunused
    -Wno-unused-parameter
    -Wwrite-strings
    -Wchar-subscripts
    -funsigned-char
    -fwrapv
    -Wno-cast-function-type-mismatch
)

target_compile_definitions(libquickjs
    PRIVATE
    CONFIG_VERSION="2025-04-26"
)

target_compile_definitions(libquickjs PRIVATE _GNU_SOURCE)

message("CMAKE_CURRENT_BINARY_DIR is ${CMAKE_CURRENT_BINARY_DIR}")

target_include_directories(
    libquickjs
    INTERFACE
    ${PROJECT_SOURCE_DIR}
)