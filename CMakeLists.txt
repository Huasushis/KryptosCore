# Copyright (c) 2026 Huasushis
# Licensed under the MIT License. See LICENSE file for details.

cmake_minimum_required(VERSION 3.14)
project(KryptosCore VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to Release if not specified (avoids 3 MB debug builds).
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Strip binaries in Release mode (GCC/Clang).
if(NOT MSVC)
    set(CMAKE_C_FLAGS_RELEASE   "-Os -DNDEBUG" CACHE STRING "" FORCE)
    set(CMAKE_CXX_FLAGS_RELEASE "-Os -DNDEBUG" CACHE STRING "" FORCE)
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE
        "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -s" CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
# Third-party dependencies
# ---------------------------------------------------------------------------

include(FetchContent)

FetchContent_Declare(
    picosha2
    GIT_REPOSITORY https://github.com/okdshin/PicoSHA2.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(picosha2)

# ---------------------------------------------------------------------------
# Core library
# ---------------------------------------------------------------------------

add_library(kryptos_core STATIC
    src/core.cpp
    src/crypto_utils.cpp
    src/manager.cpp
)

target_include_directories(kryptos_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(kryptos_core PRIVATE picosha2)

# Compiler warnings (Google-style: treat warnings as errors on CI)
if(MSVC)
    target_compile_options(kryptos_core PRIVATE /W4)
else()
    target_compile_options(kryptos_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------------------
# Console example
# ---------------------------------------------------------------------------

add_executable(kryptos example/main.cpp)
target_link_libraries(kryptos PRIVATE kryptos_core)

if(MSVC)
    target_compile_options(kryptos PRIVATE /W4)
else()
    target_compile_options(kryptos PRIVATE -Wall -Wextra -Wpedantic)
endif()

# On Windows, link user32 for clipboard API.
if(WIN32)
    target_link_libraries(kryptos PRIVATE user32)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

enable_testing()

add_executable(kryptos_tests tests/test_core.cpp)
target_link_libraries(kryptos_tests PRIVATE kryptos_core)

if(MSVC)
    target_compile_options(kryptos_tests PRIVATE /W4)
else()
    target_compile_options(kryptos_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME KryptosCoreTests COMMAND kryptos_tests)

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

install(TARGETS kryptos DESTINATION bin)
install(DIRECTORY include/kryptos DESTINATION include)
