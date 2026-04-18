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

include(FetchContent)

FetchContent_Declare(asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio
    GIT_TAG        asio-1-30-2
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(asio)

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
    src/blocklist.cpp)
target_include_directories(cloak_dns_core PUBLIC include)
target_compile_features(cloak_dns_core PUBLIC cxx_std_20)

add_executable(cloakdns src/main.cpp)
target_link_libraries(cloakdns PRIVATE asio_headers cloak_dns_core)

if(WIN32)
    target_link_libraries(cloakdns PRIVATE ws2_32 mswsock)
endif()

enable_testing()
add_subdirectory(tests)
