set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
add_subdirectory(${PROJECT_SOURCE_DIR}/dependencies/googletest)
include(GoogleTest)

function(AddTest)
  set(oneValueArgs NAME)
  set(multiValueArgs SOURCES LIBS)
  cmake_parse_arguments(ADD_TEST "${options}"
                        "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  add_executable(${ADD_TEST_NAME} ${ADD_TEST_SOURCES})
  target_link_libraries(${ADD_TEST_NAME} ${ADD_TEST_LIBS} GTest::gtest_main)
  target_include_directories(${ADD_TEST_NAME} PRIVATE ./src)
  gtest_discover_tests(${ADD_TEST_NAME})
endfunction()