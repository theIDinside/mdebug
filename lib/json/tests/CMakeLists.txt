cmake_minimum_required(VERSION 3.28)

# GoogleTest setup
if (NOT TARGET gtest)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    )

    # Avoid GoogleTest messing with compiler/linker settings on MSVC
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
else()
    message("gtest target already defined, reusing it.")
endif()
# Build the test executable
add_executable(mdbjson_tests tests.cpp)

# Link against your library and GoogleTest
target_link_libraries(mdbjson_tests
    PRIVATE
        mdbjson
        GTest::gtest
        GTest::gtest_main
)

# Ensure headers from json/include are visible
target_include_directories(mdbjson_tests
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

# Automatically discover and register tests
include(GoogleTest)
gtest_discover_tests(mdbjson_tests)