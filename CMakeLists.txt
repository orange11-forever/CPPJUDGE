cmake_minimum_required(VERSION 3.16)
project(onlinejudge-sandbox VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -O0)
else()
    add_compile_options(-O2 -DNDEBUG)
endif()

add_library(ojsandbox STATIC
    src/sandbox.cpp
    src/cgroup.cpp
    src/chroot.cpp
    src/seccomp.cpp
    src/errors.cpp
    src/config.cpp
    src/result.cpp
)

target_include_directories(ojsandbox PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

find_package(Threads REQUIRED)
target_link_libraries(ojsandbox PUBLIC Threads::Threads)

add_executable(simple_judge examples/main.cpp)
target_link_libraries(simple_judge ojsandbox)

# --- testing ---
option(BUILD_TESTING "Build and register the test suite" ON)
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
