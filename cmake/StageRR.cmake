function(stage_rr_runtime target bin_dir rr_lib_dir)
  if(NOT TARGET ${target})
    message(FATAL_ERROR "stage_rr_runtime: target '${target}' does not exist")
  endif()

  if(NOT IS_DIRECTORY "${bin_dir}")
    # Don't require it to exist yet; we'll create it
    message(STATUS "RR staging: bin dir = ${bin_dir}")
  endif()

  if(NOT IS_DIRECTORY "${rr_lib_dir}")
    message(STATUS "RR staging: lib dir = ${rr_lib_dir}")
  endif()

  # Where RR was built
  set(RR_BUILD_BIN_DIR "${RR_BINARY_OBJ_DIR}/bin")
  set(RR_BUILD_LIB_DIR "${RR_BINARY_OBJ_DIR}/lib/rr")

  # RR artifacts (stable names)
  set(RR_EXEC_STUBS
    rr_exec_stub
    rr_exec_stub_32
  )

  set(RR_SHARED_LIBS
    librraudit.so
    librraudit_32.so
    librrpage.so
    librrpage_32.so
    librrpreload.so
    librrpreload_32.so
  )

  # Ensure directory structure exists
  add_custom_command(
    TARGET ${target} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${bin_dir}"
            "${rr_lib_dir}"
    COMMENT "Creating RR runtime directories"
  )

  # Copy shared libs to rr lib dir
  foreach(lib IN LISTS RR_SHARED_LIBS)
    add_custom_command(
      TARGET ${target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
              "${RR_BUILD_LIB_DIR}/${lib}"
              "${rr_lib_dir}/${lib}"
      COMMENT "Staging RR runtime library: ${lib}"
    )
  endforeach()

  # Copy exec stubs to bin/
  foreach(stub IN LISTS RR_EXEC_STUBS)
    add_custom_command(
      TARGET ${target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
              "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${stub}"
              "${bin_dir}/${stub}"
      COMMENT "Staging RR executable: ${stub}"
    )
  endforeach()

endfunction()
