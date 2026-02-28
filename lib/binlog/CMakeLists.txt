cmake_minimum_required(VERSION 3.20)
project(binlog VERSION 1.0.0 LANGUAGES CXX)

# C++23 required
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Library sources
add_library(binlog
  src/logger.cpp
)

target_include_directories(binlog
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(binlog PUBLIC cxx_std_23)

# Generate format string index
# Users should run this script before building to index their log format strings
add_custom_target(generate_format_index
  COMMAND python ${CMAKE_CURRENT_SOURCE_DIR}/scripts/format_indexer.py
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "Generating format string index"
)

# Decoder utility
add_executable(binlog_decoder
  tools/decoder/main.cpp
  tools/decoder/decoder.cpp
)

target_include_directories(binlog_decoder PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}  # For accessing generated format files
)

target_compile_features(binlog_decoder PRIVATE cxx_std_23)

# Installation
install(TARGETS binlog
  EXPORT binlogTargets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
)

install(DIRECTORY include/binlog
  DESTINATION include
)

install(TARGETS binlog_decoder
  DESTINATION bin
  RENAME logdecode
)

install(FILES scripts/format_indexer.py
  DESTINATION share/binlog
)

# Export configuration
install(EXPORT binlogTargets
  FILE binlogTargets.cmake
  NAMESPACE binlog::
  DESTINATION lib/cmake/binlog
)

# Create package config
include(CMakePackageConfigHelpers)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/binlogConfig.cmake"
  INSTALL_DESTINATION lib/cmake/binlog
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/binlogConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/binlogConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/binlogConfigVersion.cmake"
  DESTINATION lib/cmake/binlog
)
