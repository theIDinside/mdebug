set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
include(GoogleTest)

function(BuildTestSubject)
  set(oneValueArgs NAME)
  set(multiValueArgs SOURCES LIBS INCLUDE_DIR)
  cmake_parse_arguments(BUILD_TEST "${options}"
                        "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  add_executable(${BUILD_TEST_NAME} ${BUILD_TEST_SOURCES})
  set_target_properties(${BUILD_TEST_NAME} PROPERTIES LINKER_LANGUAGE CXX)  # Specify the linker languag
  set_target_properties(${BUILD_TEST_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
  target_link_libraries(${BUILD_TEST_NAME} ${BUILD_TEST_LIBS})
  target_include_directories(${BUILD_TEST_NAME} PRIVATE ./src ${BUILD_TEST_INCLUDE_DIR})
  if(USE_DWARF5)
    target_compile_options(${BUILD_TEST_NAME} PRIVATE -O0 -g3 -gdwarf-5 -fdebug-types-section)
  else()
    target_compile_options(${BUILD_TEST_NAME} PRIVATE -O0 -g3)
  endif()
endfunction()

function(AddTest)
  set(oneValueArgs NAME)
  set(multiValueArgs SOURCES LIBS INCLUDE_DIR)
  cmake_parse_arguments(ADD_TEST "${options}"
                        "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  add_executable(${ADD_TEST_NAME} ${ADD_TEST_SOURCES})
  target_link_libraries(${ADD_TEST_NAME} ${ADD_TEST_LIBS} GTest::gtest_main)
  target_include_directories(${ADD_TEST_NAME} PRIVATE ./src ${ADD_TEST_INCLUDE_DIR})
  gtest_discover_tests(${ADD_TEST_NAME})
endfunction()