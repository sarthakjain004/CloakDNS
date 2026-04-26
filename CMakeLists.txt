cmake_minimum_required(VERSION 3.25)
project(cloakdns CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Sanitizer selector: off | asan | ubsan | asan+ubsan | tsan
# GCC/Clang only — MSVC has AddressSanitizer since VS 2019 but the
# runtime doesn't ship with BuildTools, so gate to non-MSVC here.
set(CLOAKDNS_SANITIZE "off" CACHE STRING
    "Enable sanitizer: off | asan | ubsan | asan+ubsan | tsan")
if(NOT MSVC AND NOT CLOAKDNS_SANITIZE STREQUAL "off")
    set(_san_flags "")
    if(CLOAKDNS_SANITIZE MATCHES "asan")
        list(APPEND _san_flags -fsanitize=address -fno-omit-frame-pointer)
    endif()
    if(CLOAKDNS_SANITIZE MATCHES "ubsan")
        list(APPEND _san_flags -fsanitize=undefined -fno-sanitize-recover=all)
    endif()
    if(CLOAKDNS_SANITIZE STREQUAL "tsan")
        list(APPEND _san_flags -fsanitize=thread)
    endif()
    if(_san_flags)
        add_compile_options(${_san_flags} -g -O1)
        add_link_options(${_san_flags})
        message(STATUS "CloakDNS sanitizer: ${CLOAKDNS_SANITIZE}")
    endif()
endif()

include(FetchContent)

FetchContent_Declare(asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio
    GIT_TAG        asio-1-30-2
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(asio)

FetchContent_Declare(tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus
    GIT_TAG        v3.4.0
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(tomlplusplus)

add_library(asio_headers INTERFACE)
target_include_directories(asio_headers INTERFACE
    ${asio_SOURCE_DIR}/asio/include)
target_compile_definitions(asio_headers INTERFACE ASIO_STANDALONE)

if(WIN32)
    target_compile_definitions(asio_headers INTERFACE
        _WIN32_WINNT=0x0A00)
endif()

add_library(cloak_dns_core STATIC
    src/dns_parser.cpp
    src/dns_writer.cpp
    src/blocklist.cpp
    src/upstream.cpp
    src/uncloaker.cpp
    src/cache.cpp
    src/edns_padding.cpp
    src/config.cpp
    src/query_log.cpp
    src/paths.cpp
    src/privilege.cpp)
target_include_directories(cloak_dns_core PUBLIC include)
target_compile_features(cloak_dns_core PUBLIC cxx_std_20)
target_link_libraries(cloak_dns_core PUBLIC asio_headers tomlplusplus::tomlplusplus)

if(WIN32)
    target_link_libraries(cloak_dns_core PUBLIC ws2_32 mswsock)
endif()

add_executable(cloakdns src/main.cpp)
target_link_libraries(cloakdns PRIVATE cloak_dns_core)

enable_testing()
add_subdirectory(tests)
