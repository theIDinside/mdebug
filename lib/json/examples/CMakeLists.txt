cmake_minimum_required(VERSION 3.15)
project(libjson VERSION 0.1.0 LANGUAGES CXX)

# Require modern C++
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

set(JSON_SOURCES src/json.cpp include/json/json.h src/parser.cpp)

add_library(mdbjson STATIC ${JSON_SOURCES})
target_include_directories(mdbjson PUBLIC ${PROJECT_SOURCE_DIR}/include)

# Subdirectories for examples/tests
option(MDBJSON_BUILD_EXAMPLES "Build examples" OFF)
option(MDBJSON_BUILD_TESTS "Build tests" OFF)

if(MDBJSON_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(MDBJSON_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()