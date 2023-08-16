cmake_minimum_required(VERSION 3.22)
project(midas LANGUAGES CXX C ASM)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(MIDAS_SOURCES
  src/main.cpp
  src/utils/logger.cpp
  src/utils/logger.h
  src/tracer.cpp
  src/tracer.h
  src/supervisor.cpp
  src/supervisor.h
  src/ptracestop_handlers.cpp
  src/ptracestop_handlers.h
  src/common.cpp
  src/common.h
  src/ptrace.cpp
  src/ptrace.h
  src/task.cpp
  src/task.h
  src/notify_pipe.cpp
  src/notify_pipe.h
  src/awaiter.cpp
  src/awaiter.h
  src/breakpoint.cpp
  src/breakpoint.h
  src/so_loading.cpp
  src/so_loading.h
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
  src/symbolication/callstack.cpp
  src/symbolication/callstack.h
  src/symbolication/disassemble.cpp
  src/symbolication/disassemble.h
  src/symbolication/dwarf_frameunwinder.cpp
  src/symbolication/dwarf_frameunwinder.h
  src/symbolication/dwarf_expressions.cpp
  src/symbolication/dwarf_expressions.h
  src/lib/lockguard.h
  src/interface/dap/interface.cpp
  src/interface/dap/interface.h
  src/interface/dap/commands.cpp
  src/interface/dap/commands.h
  src/interface/dap/dap_defs.h
  src/interface/dap/parse_buffer.cpp
  src/interface/dap/parse_buffer.h
  src/interface/dap/events.cpp
  src/interface/dap/events.h
  src/interface/dap/types.cpp
  src/interface/dap/types.h
  src/interface/pty.cpp
  src/interface/pty.h
  src/utils/base64.cpp
  src/utils/base64.h
)

set(COMMON_SRC src/common.cpp src/common.h)

set(MIDAS_SPINLOCK src/lib/spinlock.cpp src/lib/spinlock.h)
add_library(mdb_spinlock STATIC ${MIDAS_SPINLOCK})
add_library(zydis STATIC dependencies/zydis/Zydis.c dependencies/zydis/Zydis.h)
target_include_directories(zydis PRIVATE ./dependencies/zydis)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(COMMON_FLAGS "-msse2 -D__MMX__ -D__SSE__ -D__SSE2__ -march=native -mavx -mavx2")
set(MIDAS_DEBUG_FLAGS "-g3 -O0 -Wall -Wextra -fpermissive")
set(MIDAS_RELEASE_FLAGS "-O3 -Wall -Wextra -Werror -flto")
set(MIDAS_TEST_FLAGS "${MIDAS_DEBUG_FLAGS}")

set(CMAKE_CXX_FLAGS_DEBUG "${COMMON_FLAGS} ${MIDAS_DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_RELEASE "${COMMON_FLAGS} ${MIDAS_RELEASE_FLAGS}")
message("Build type for project: ${CMAKE_BUILD_TYPE}")
# Generate syscalls.def
execute_process(COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/generate/syscalls.py WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(test)
enable_testing()
# Unit Testing (using googletest)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
add_subdirectory(dependencies/googletest)

add_executable(
  parse_dap_requests
  test/unittest/parse_dap_requests.cpp
  src/interface/dap/parse_buffer.cpp
  src/interface/dap/parse_buffer.h
  src/utils/logger.cpp
  ${COMMON_SRC}
)

target_link_libraries(
  parse_dap_requests
  GTest::gtest_main
  fmt::fmt
  mdb_spinlock
  nlohmann_json::nlohmann_json
)

add_executable(
  base64_encoding
  test/unittest/base64.cpp
  src/utils/base64.cpp
  src/utils/logger.cpp
  ${COMMON_SRC}
)

target_link_libraries(
  base64_encoding
  GTest::gtest_main
  fmt::fmt
  mdb_spinlock
)

include(GoogleTest)
gtest_discover_tests(parse_dap_requests)
gtest_discover_tests(base64_encoding)

# Add the fantastic libfmt library
add_subdirectory(dependencies/fmt)
add_executable(mdb ${MIDAS_SOURCES})
set_target_properties(mdb PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set_property(TARGET mdb PROPERTY CXX_STANDARD 23)

# Add the json library
set(JSON_Install OFF CACHE INTERNAL "")
add_subdirectory(dependencies/nlohmann_json)

target_link_libraries(mdb fmt::fmt mdb_spinlock nlohmann_json::nlohmann_json zydis)
target_include_directories(mdb PUBLIC ./dependencies)

find_program(NODEJS "node")

# The Driver Test Suite
if(NODEJS)
  # Sub-test suites.
  set(DRIVER_TEST_SUITES
      disassemble 
      exited
      initialize 
      launch 
      nextInstruction
      nextLine 
      setBreakpoints 
      setInstructionBreakpoints 
      unwinder
      threadExited
      moduleEvent
      threads
  )

  # These define 
  set(disassemble "backAndForward")
  set(exited "programExit")
  set(initialize)
  set(launch "launch" "launchToMain" "launchThenDisconnect")
  set(nextInstruction "oneInstruction")
  set(nextLine "nextLineOverFunction")
  set(setBreakpoints "set4Breakpoints")
  set(setInstructionBreakpoints "set1Bp") 
  set(unwinder "insidePrologue" "normal" "insideEpilogue" "unwindFromSharedObject")
  set(threadExited "see9ThreadExits")
  set(moduleEvent "6modules")
  set(threads "threads")

  foreach(driver_test ${DRIVER_TEST_SUITES})
    list(LENGTH ${driver_test} LIST_LENGTH)
    if(${LIST_LENGTH} EQUAL 0)
      add_test(NAME DriverTest.${driver_test} COMMAND node ${CMAKE_CURRENT_SOURCE_DIR}/test/driver/${driver_test}.js ${CMAKE_BINARY_DIR} ${test})
    else()
    message("Suite ${driver_test}:")
      foreach(test ${${driver_test}})
        message("  - ${test}")
        add_test(NAME DriverTest.${driver_test}.${test} COMMAND node ${CMAKE_CURRENT_SOURCE_DIR}/test/driver/${driver_test}.js ${CMAKE_BINARY_DIR} ${test})
      endforeach()
    endif()
  endforeach()
endif()

# To be able to print backtrace with symbols (see `man backtrace`)
target_link_options(mdb PRIVATE -rdynamic)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(mdb PRIVATE MDB_DEBUG)
endif()