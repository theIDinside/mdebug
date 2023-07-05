cmake_minimum_required(VERSION 3.22)
project(midas LANGUAGES CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD_REQUIRED 23)
set(MIDAS_SOURCES
  src/main.cpp
  src/tracer.cpp
  src/tracer.h
  src/target.cpp
  src/target.h
  src/common.cpp
  src/common.h
  src/ptrace.cpp
  src/ptrace.h
  src/task.cpp
  src/task.h
  src/breakpoint.cpp
  src/breakpoint.h
  src/posix/argslist.cpp
  src/posix/argslist.h
  src/symbolication/elf.cpp
  src/symbolication/elf.h
  src/symbolication/objfile.cpp
  src/symbolication/objfile.h
  src/symbolication/cu.cpp
  src/symbolication/cu.h
  src/symbolication/dwarf.cpp
  src/symbolication/dwarf.h
  src/symbolication/lnp.cpp
  src/symbolication/lnp.h
  src/symbolication/elf_symbols.cpp
  src/symbolication/elf_symbols.h
  src/symbolication/block.cpp
  src/symbolication/block.h
  src/symbolication/type.cpp
  src/symbolication/type.h
  src/lib/lockguard.h
)

set(MIDAS_SPINLOCK src/lib/spinlock.cpp src/lib/spinlock.h)
add_library(mdb_spinlock STATIC ${MIDAS_SPINLOCK})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(COMMON_FLAGS "-msse2 -D__MMX__ -D__SSE__ -D__SSE2__ -march=native -mavx -mavx2")
set(MIDAS_DEBUG_FLAGS "-g3 -O0 -Wall -Wextra -fpermissive")
set(MIDAS_RELEASE_FLAGS "-O3 -Wall -Wextra -Werror -flto")
set(MIDAS_TEST_FLAGS "${MIDAS_DEBUG_FLAGS}")

set(CMAKE_CXX_FLAGS_DEBUG "${COMMON_FLAGS} ${MIDAS_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_RELEASE "${COMMON_FLAGS} ${MIDAS_RELEASE_FLAGS}")

set(MDB_TESTS
  helloworld
  threads
)


function(build_tests tests)
    foreach(target_name ${tests})
        set(target_source ${CMAKE_CURRENT_SOURCE_DIR}/test/${target_name}.cpp ${CMAKE_CURRENT_SOURCE_DIR}/test/spinlock.cpp)
        add_executable(${target_name} ${target_source})  # Change the file extension if necessary
        set_target_properties(${target_name} PROPERTIES LINKER_LANGUAGE CXX)  # Specify the linker languag
        set_target_properties(${target_name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    endforeach()
endfunction()

build_tests("${MDB_TESTS}")

enable_testing()
# Generate syscalls.def
execute_process(COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/generate/syscalls.py WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(./dependencies/fmt)
add_executable(mdb ${MIDAS_SOURCES})
set_target_properties(mdb PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set_property(TARGET mdb PROPERTY CXX_STANDARD 23)
target_link_libraries(mdb fmt::fmt mdb_spinlock)
target_include_directories(mdb PUBLIC ./dependencies)

# To be able to print backtrace with symbols
target_link_options(mdb PRIVATE -rdynamic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(mdb PRIVATE MDB_DEBUG)
endif()