# Copyright (c) 2026 Huasushis
# Licensed under the MIT License. See LICENSE file for details.

cmake_minimum_required(VERSION 3.14)
project(KryptosCore VERSION 1.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to Release if not specified (avoids oversized debug builds).
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
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
    src/webdav.cpp
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
add_library(kryptos_config STATIC src/webdav_config.cpp src/credentials.cpp)
target_link_libraries(kryptos_config PUBLIC kryptos_core)
if(WIN32)
    target_link_libraries(kryptos_config PRIVATE advapi32)
elseif(APPLE)
    target_link_libraries(kryptos_config PRIVATE "-framework Security" "-framework CoreFoundation")
else()
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBSECRET QUIET IMPORTED_TARGET libsecret-1)
        if(LIBSECRET_FOUND)
            target_compile_definitions(kryptos_config PRIVATE KRYPTOS_HAS_LIBSECRET)
            target_link_libraries(kryptos_config PRIVATE PkgConfig::LIBSECRET)
        endif()
    endif()
endif()
set(KRYPTOS_VERSION "${PROJECT_VERSION}" CACHE STRING "Release version embedded in the CLI")
add_library(kryptos_update STATIC src/update.cpp)
target_link_libraries(kryptos_update PUBLIC kryptos_core)
target_compile_definitions(kryptos_update PRIVATE KRYPTOS_VERSION="${KRYPTOS_VERSION}")
add_library(kryptos_webdav_http STATIC src/webdav_http.cpp src/update_http.cpp)
target_link_libraries(kryptos_webdav_http PUBLIC kryptos_core)
if(WIN32)
    target_link_libraries(kryptos_webdav_http PRIVATE winhttp)
else()
    find_package(CURL REQUIRED)
    target_link_libraries(kryptos_webdav_http PRIVATE CURL::libcurl)
endif()
target_link_libraries(kryptos PRIVATE kryptos_webdav_http kryptos_update kryptos_config)

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
add_executable(kryptos_webdav_tests tests/test_webdav.cpp)
target_link_libraries(kryptos_webdav_tests PRIVATE kryptos_core)
add_test(NAME KryptosWebDavTests COMMAND kryptos_webdav_tests)
add_executable(kryptos_update_tests tests/test_update.cpp)
target_link_libraries(kryptos_update_tests PRIVATE kryptos_update)
add_test(NAME KryptosUpdateTests COMMAND kryptos_update_tests)
add_executable(kryptos_config_tests tests/test_webdav_config.cpp)
target_link_libraries(kryptos_config_tests PRIVATE kryptos_config)
add_test(NAME KryptosConfigTests COMMAND kryptos_config_tests)
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME KryptosUpdateApplyTests COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_update_apply.py --binary $<TARGET_FILE:kryptos_update_tests>)
    add_test(NAME KryptosWebDavHttpTests COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_webdav_http.py --binary $<TARGET_FILE:kryptos>)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

install(TARGETS kryptos DESTINATION bin)
install(DIRECTORY include/kryptos DESTINATION include)
