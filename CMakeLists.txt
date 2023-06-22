cmake_minimum_required(VERSION 3.22)
project(midas)

set(SOURCES
  ./src/main.cpp
)

add_subdirectory(./dependencies/fmt)
add_executable(mdb ${SOURCES})

target_link_libraries(mdb fmt::fmt-header-only)