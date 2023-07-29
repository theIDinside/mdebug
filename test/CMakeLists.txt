cmake_minimum_required(VERSION 3.22)
project(mdb_tests CXX C ASM)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(MDB_TESTS
  helloworld
  threads_shared # all tests that uses shared libraries, must have shared in their name
  stackframes
  next
  lib_shared # all tests that uses shared libraries, must have shared in their name
)

add_library(metricsconv SHARED dynamic_lib.cpp dynamic_lib.h)
set_target_properties(metricsconv PROPERTIES PUBLIC_HEADER test/dynamic_lib.h)
set_target_properties(metricsconv PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

function(build_tests tests)
    foreach(target_name ${tests})
        set(target_source ${CMAKE_CURRENT_SOURCE_DIR}/${target_name}.cpp ${CMAKE_CURRENT_SOURCE_DIR}/spinlock.cpp)
        add_executable(${target_name} ${target_source})  # Change the file extension if necessary
        if(${target_name} MATCHES "shared")
          target_link_libraries(${target_name} metricsconv)
        endif()
        set_target_properties(${target_name} PROPERTIES LINKER_LANGUAGE CXX)  # Specify the linker languag
        set_target_properties(${target_name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
    endforeach()
endfunction()

build_tests("${MDB_TESTS}")

message("Test build type: ${CMAKE_BUILD_TYPE}")