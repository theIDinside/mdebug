cmake_minimum_required(VERSION 3.22)
project(midas LANGUAGES CXX C ASM)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(USE_DWARF5 "Setting to make sure clang or gcc uses DWARF5 for it's debug symbols" OFF)
option(BUILD_MDB_TESTS "Setting that configures & builds test subjects" OFF)
option(CLANG_TIDY_CHECK "Configure clang-tidy to run during build" OFF)

find_package(PkgConfig REQUIRED)
set(ENV{PKG_CONFIG_PATH} "/home/prometheus/dev/cx/spidermonkey/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(SPIDERMONKEY REQUIRED "mozjs-136a1")

set(MDB_ROOT ${PROJECT_SOURCE_DIR})

string(TOUPPER ${CMAKE_BUILD_TYPE} MIDAS_BUILD_TYPE)
set(MIDAS_SOURCES
  # root
  src/awaiter.cpp
  src/awaiter.h
  src/bp.cpp
  src/bp.h
  src/bp_spec.cpp
  src/bp_spec.h
  src/common.cpp
  src/common.h
  src/event_queue_event_param.h
  src/event_queue.cpp
  src/event_queue.h
  src/main.cpp
  src/mdb_config.cpp
  src/mdb_config.h
  src/notify_pipe.cpp
  src/notify_pipe.h
  src/register_description.cpp
  src/register_description.h
  src/so_loading.cpp
  src/so_loading.h
  src/supervisor.cpp
  src/supervisor.h
  src/task_scheduling.cpp
  src/task_scheduling.h
  src/task.cpp
  src/task.h
  src/tracer.cpp
  src/tracer.h

  #sys
  src/mdbsys/ptrace.cpp
  src/mdbsys/ptrace.h

  # events
  src/events/event.cpp
  src/events/event.h
  # lib
  src/lib/arena_allocator.cpp
  src/lib/arena_allocator.h
  src/lib/lockguard.h
  # symbolication
  src/symbolication/block.cpp
  src/symbolication/block.h
  src/symbolication/callstack.cpp
  src/symbolication/callstack.h
  src/symbolication/cu_symbol_info.cpp
  src/symbolication/cu_symbol_info.h
  src/symbolication/disassemble.cpp
  src/symbolication/disassemble.h
  src/symbolication/dwarf_binary_reader.cpp
  src/symbolication/dwarf_binary_reader.h
  src/symbolication/dwarf_expressions.cpp
  src/symbolication/dwarf_expressions.h
  src/symbolication/dwarf_frameunwinder.cpp
  src/symbolication/dwarf_frameunwinder.h
  src/symbolication/dwarf.h
  src/symbolication/dwarf/debug_info_reader.cpp
  src/symbolication/dwarf/debug_info_reader.h
  src/symbolication/dwarf/die_iterator.cpp
  src/symbolication/dwarf/die_iterator.h
  src/symbolication/dwarf/die_ref.cpp
  src/symbolication/dwarf/die_ref.h
  src/symbolication/dwarf/die.cpp
  src/symbolication/dwarf/die.h
  src/symbolication/dwarf/lnp.cpp
  src/symbolication/dwarf/lnp.h
  src/symbolication/dwarf/name_index.cpp
  src/symbolication/dwarf/name_index.h
  src/symbolication/dwarf/reader_funcs.h
  src/symbolication/dwarf/rnglists.cpp
  src/symbolication/dwarf/rnglists.h
  src/symbolication/dwarf/typeread.cpp
  src/symbolication/dwarf/typeread.h
  src/symbolication/dwarf/unit_header.cpp
  src/symbolication/dwarf/unit_header.h
  src/symbolication/elf_symbols.h
  src/symbolication/elf.cpp
  src/symbolication/elf.h
  src/symbolication/fnsymbol.cpp
  src/symbolication/fnsymbol.h
  src/symbolication/objfile.cpp
  src/symbolication/objfile.h
  src/symbolication/type.cpp
  src/symbolication/type.h
  src/symbolication/value_visualizer.cpp
  src/symbolication/value_visualizer.h
  src/symbolication/value.cpp
  src/symbolication/value.h
  src/symbolication/variable_reference.cpp
  src/symbolication/variable_reference.h
  # tasks
  src/tasks/dwarf_unit_data.cpp
  src/tasks/dwarf_unit_data.h
  src/tasks/index_die_names.cpp
  src/tasks/index_die_names.h
  # utils
  src/utils/base64.cpp
  src/utils/base64.h
  src/utils/byte_buffer.cpp
  src/utils/byte_buffer.h
  src/utils/debugger_thread.cpp
  src/utils/debugger_thread.h
  src/utils/logger.cpp
  src/utils/logger.h
  src/utils/scoped_fd.cpp
  src/utils/scoped_fd.h
  src/utils/sync_barrier.cpp
  src/utils/sync_barrier.h
  src/utils/thread_pool.cpp
  src/utils/thread_pool.h
  src/utils/worker_task.cpp
  src/utils/worker_task.h
  src/utils/xml.cpp
  src/utils/xml.h

  src/tracee/util.cpp
  src/tracee/util.h

  # Various interfaces
  src/interface/console_command.cpp
  src/interface/console_command.h
  src/interface/dap/commands.cpp
  src/interface/dap/commands.h
  src/interface/dap/dap_defs.h
  src/interface/dap/events.cpp
  src/interface/dap/events.h
  src/interface/dap/interface.cpp
  src/interface/dap/interface.h
  src/interface/dap/parse_buffer.cpp
  src/interface/dap/parse_buffer.h
  src/interface/dap/types.cpp
  src/interface/dap/types.h
  src/interface/pty.cpp
  src/interface/pty.h

  # Gdb Remote interface
  src/interface/remotegdb/connection.cpp
  src/interface/remotegdb/connection.h
  src/interface/remotegdb/deserialization.cpp
  src/interface/remotegdb/deserialization.h
  src/interface/remotegdb/shared.cpp
  src/interface/remotegdb/shared.h
  src/interface/remotegdb/stopreply_parser.cpp
  src/interface/remotegdb/stopreply_parser.h
  src/interface/remotegdb/target_description.cpp
  src/interface/remotegdb/target_description.h
  src/interface/remotegdb/wait_event_parser.cpp
  src/interface/remotegdb/wait_event_parser.h

  # Tracee Interfaces
  src/interface/tracee_command/gdb_remote_commander.cpp
  src/interface/tracee_command/gdb_remote_commander.h
  src/interface/tracee_command/ptrace_commander.cpp
  src/interface/tracee_command/ptrace_commander.h
  src/interface/tracee_command/tracee_command_interface.cpp
  src/interface/tracee_command/tracee_command_interface.h

  # Interpreter
  src/mdbjs/bpjs.cpp
  src/mdbjs/bpjs.h
  src/mdbjs/event_dispatcher.cpp
  src/mdbjs/event_dispatcher.h
  src/mdbjs/framejs.cpp
  src/mdbjs/framejs.h
  src/mdbjs/jsobject.h
  src/mdbjs/mdbjs.cpp
  src/mdbjs/mdbjs.h
  src/mdbjs/taskinfojs.cpp
  src/mdbjs/taskinfojs.h
  src/mdbjs/util.cpp
  src/mdbjs/util.h
  src/mdbjs/variablejs.cpp
  src/mdbjs/variablejs.h
)

set(COMMON_SRC src/common.cpp src/common.h)

set(MIDAS_SPINLOCK src/lib/spinlock.cpp src/lib/spinlock.h)
add_library(mdb_spinlock STATIC ${MIDAS_SPINLOCK})
add_library(zydis STATIC dependencies/zydis/Zydis.c dependencies/zydis/Zydis.h)
target_include_directories(zydis PRIVATE ./dependencies/zydis)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(COMMON_FLAGS "-msse2 -D__MMX__ -D__SSE__ -D__SSE2__ -march=native -mavx -mavx2")
set(MIDAS_DEBUG_FLAGS "-g3 -O0 -fpermissive")
set(MIDAS_TEST_FLAGS "${MIDAS_DEBUG_FLAGS}")

if(USE_DWARF5)
  set(MIDAS_DEBUG_FLAGS "${MIDAS_DEBUG_FLAGS} -gdwarf-5 -fdebug-types-section")
  message("Configuring compiler to emit DWARF version 5 debug symbols")
else()
  message("Configuring compiler to emit DWARF version 4 debug symbols")
  set(MIDAS_DEBUG_FLAGS "${MIDAS_DEBUG_FLAGS} -gdwarf-4")
endif()

set(CMAKE_CXX_FLAGS_DEBUG "${COMMON_FLAGS} ${MIDAS_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_RELEASE "${COMMON_FLAGS} ${MIDAS_RELEASE_FLAGS}")
message("Build type for project: ${CMAKE_BUILD_TYPE}")
# Generate syscalls.def
execute_process(COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/generate/syscalls.py WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# Add the fantastic libfmt library
add_subdirectory(dependencies/fmt)
add_executable(mdb ${MIDAS_SOURCES})
set_target_properties(mdb PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set_property(TARGET mdb PROPERTY CXX_STANDARD 23)

# Add the json library
set(JSON_Install OFF CACHE INTERNAL "")
add_subdirectory(dependencies/nlohmann_json)

target_link_libraries(mdb fmt::fmt mdb_spinlock nlohmann_json::nlohmann_json zydis ${SPIDERMONKEY_LIBRARIES})
# Add the include directories
target_include_directories(mdb PRIVATE ${SPIDERMONKEY_INCLUDE_DIRS})
# Add the library directories
target_link_directories(mdb PRIVATE ${SPIDERMONKEY_LIBRARY_DIRS})
# Link the libraries to your target

target_include_directories(mdb PUBLIC ./dependencies)
target_include_directories(mdb PUBLIC ./src)

message("Test & building test subjects has been configured to ${BUILD_MDB_TESTS}")
if(BUILD_MDB_TESTS)
  message("Testing enabled...")
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/dependencies/googletest)
  add_subdirectory(test)
  enable_testing()
  # Unit Testing (using googletest)
  include(cmake/AddTest.cmake)
  AddTest(NAME base64_encoding
    SOURCES test/unittest/base64.cpp src/utils/base64.cpp src/utils/logger.cpp ${COMMON_SRC}
    LIBS fmt::fmt mdb_spinlock
  )

  AddTest(NAME test_utils
    SOURCES test/unittest/util_testing.cpp src/common.cpp src/utils/logger.cpp src/lib/spinlock.cpp src/interface/remotegdb/deserialization.cpp
    LIBS fmt::fmt mdb_spinlock)

  AddTest(NAME expected_tests
    SOURCES test/unittest/expected_tests.cpp
    LIBS fmt::fmt)

  AddTest(NAME xml_tests
    SOURCES test/unittest/xml_tests.cpp src/utils/xml.cpp src/utils/xml.h
    LIBS fmt::fmt)

  # The Driver Test Suite
  find_program(NODEJS "node")
  if(NODEJS)
    message("Exporting tests using MDB test exporter: ${CMAKE_CURRENT_SOURCE_DIR}/test/export_tests.js")
    execute_process(COMMAND node ${CMAKE_CURRENT_SOURCE_DIR}/test/export_tests.js
    RESULT_VARIABLE GENERATOR_EXIT_CODE
    ERROR_VARIABLE GENERATOR_ERROR
    OUTPUT_VARIABLE GENERATOR_OUTPUT)
    if(GENERATOR_EXIT_CODE EQUAL 0)
      message(STATUS "CTest suites generated successfully: ${GENERATOR_OUTPUT}")
      include(${CMAKE_CURRENT_SOURCE_DIR}/test/driver/DriverTests.cmake)
    else()
      message(WARNING "Could not generate test suite configuration. Error message:\n${GENERATOR_OUTPUT}\nGenerator exited with code ${GENERATOR_EXIT_CODE}")
    endif()
  endif()
endif()

# To be able to print backtrace with symbols (see `man backtrace`)
target_link_options(mdb PRIVATE -rdynamic)
if(MIDAS_BUILD_TYPE STREQUAL "DEBUG")
  target_compile_definitions(mdb PRIVATE MDB_DEBUG=1 DEBUG)
elseif(MIDAS_BUILD_TYPE STREQUAL "RELEASE")
  target_compile_definitions(mdb PRIVATE MDB_DEBUG=0)
endif()

target_link_options(mdb PRIVATE "-fuse-ld=lld")

# Check if the compiler name contains gcc or clang
if (${CMAKE_CXX_COMPILER_ID} MATCHES "GNU")
  message("Compiler is GNU, and it gives false positives on dangling references for libfmt, making release builds impossible. Therefore gcc uses -Wno-error=dangling-reference")
  set(MIDAS_RELEASE_FLAGS "-O3 -Wall -Wextra -Werror -flto -Wno-error=dangling-reference")
  target_compile_definitions(mdb PRIVATE COMPILERUSED_GCC)
elseif ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
  # clang using GNU's stdlib ranges, is.... iffy at the moment.
  target_compile_definitions(mdb PUBLIC JSON_HAS_RANGES=0)
  set(MIDAS_RELEASE_FLAGS "-O3 -Wall -Wextra -Werror -flto")
else ()
  error("Unknown compiler")
endif ()

set(CMAKE_CXX_CLANG_TIDY
  clang-tidy;
  -header-filter=.*;
  -checks=*,modernize-*;)

if(CLANG_TIDY_CHECK)
  find_program(CLANG_TIDY_EXE NAMES "clang-tidy" REQUIRED)
  set(CLANG_TIDY_COMMAND "${CMAKE_CXX_CLANG_TIDY}" "-checks=-*")

  # set CXX_CLANG_TIDY property after defining the target
  set_target_properties(mdb PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY_COMMAND}")
endif()
