# Build test programs and register CTest tests.
# Included from root CMakeLists.txt when BUILD_TESTING=ON.

enable_language(C)  # test programs are plain C

set(TEST_PROGRAMS
    ok
    nonzero_exit
    segfault
    tle
    mle
    ole
    seccomp_violation
)

set(TEST_BIN_DIR "${CMAKE_CURRENT_BINARY_DIR}/bin")
file(MAKE_DIRECTORY "${TEST_BIN_DIR}")

foreach(name ${TEST_PROGRAMS})
    add_executable(test_${name} "${CMAKE_CURRENT_SOURCE_DIR}/${name}.c")
    target_link_options(test_${name} PRIVATE -static)
    set_target_properties(test_${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${TEST_BIN_DIR}"
    )
endforeach()

# Register the test runner with CTest.
# It finds the compiled test binaries in TEST_BIN_DIR and uses
# simple_judge (a dependency) to execute each.
add_test(
    NAME cppjudge_sandbox
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh"
           --build-dir "${CMAKE_BINARY_DIR}"
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
)

# Make sure simple_judge is built before testing.
set_tests_properties(cppjudge_sandbox PROPERTIES
    DEPENDS simple_judge
)
