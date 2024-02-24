cmake_minimum_required(VERSION 3.22)
project(mdb_tests CXX C ASM)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# set(CMAKE_CXX_FLAGS_DEBUG "${COMMON_FLAGS} -g3 -fomit-frame-pointer")
set(CMAKE_CXX_FLAGS_DEBUG "${COMMON_FLAGS} -g3")

set(MDB_TESTS
  helloworld
  pause
  threads_shared # all tests that uses shared libraries, must have shared in their name
  stackframes
  next
  lib_shared # all tests that uses shared libraries, must have shared in their name
  stupid_shared
  basetypes # testing of variable symbol parsing for base types and POD types
  variables
)

# For tests with additional sources (beyond the sources with the same name of the test, that is)
# name their variables by their names with _SOURCES appended
set(stupid_shared_SOURCES todo.cpp)

add_library(metricsconv SHARED dynamic_lib.cpp dynamic_lib.h)
set_target_properties(metricsconv PROPERTIES PUBLIC_HEADER test/dynamic_lib.h)
set_target_properties(metricsconv PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

function(build_tests tests)
  foreach(target_name ${tests})
    set(target_source ${CMAKE_CURRENT_SOURCE_DIR}/${target_name}.cpp ${CMAKE_CURRENT_SOURCE_DIR}/spinlock.cpp)
    if(DEFINED ${target_name}_SOURCES)
      set(src_get "${target_name}_SOURCES")
      set(target_source ${target_source} ${${src_get}})
    endif()
    add_executable(${target_name} ${target_source})  # Change the file extension if necessary
    if(${target_name} MATCHES "shared")
      message("${target_name} compiled with libmetricsconv")
      target_link_libraries(${target_name} metricsconv)
    endif()
    set_target_properties(${target_name} PROPERTIES LINKER_LANGUAGE CXX)  # Specify the linker languag
    set_target_properties(${target_name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

    if(USE_DWARF5)
      target_compile_options(${target_name} PRIVATE -O0 -g3 -gdwarf-5 -fdebug-types-section)
    else()
      target_compile_options(${target_name} PRIVATE -O0 -g3)
    endif()
  endforeach()
endfunction()

build_tests("${MDB_TESTS}")

# builds a test executable that has default settings
function(build_test)
  set(oneValueArgs NAME)
  set(multiValueArgs SOURCES)
  cmake_parse_arguments(BUILD_TEST "${options}"
                        "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  add_executable(${BUILD_TEST_NAME} ${BUILD_TEST_SOURCES})
  set_target_properties(${BUILD_TEST_NAME} PROPERTIES LINKER_LANGUAGE CXX)  # Specify the linker languag
  set_target_properties(${BUILD_TEST_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
  if(USE_DWARF5)
    target_compile_options(${BUILD_TEST_NAME} PRIVATE -O0 -g3 -gdwarf-5 -fdebug-types-section)
  else()
    target_compile_options(${BUILD_TEST_NAME} PRIVATE -O0 -g3)
  endif()
endfunction()

build_test(
  NAME templated
  SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/templated_code/template_main.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/templated_code/template_foo.cpp
)

build_test(
  NAME readMemory
  SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/readMemory.cpp
)

build_test(
  NAME functionBreakpoints
  SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/functionBreakpoints.cpp
)


message("Test build type: ${CMAKE_BUILD_TYPE}")