include(FetchContent)

FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest
    GIT_TAG        v1.15.2
    GIT_SHALLOW    TRUE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(cloak_tests test_dns_parser.cpp)
target_include_directories(cloak_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cloak_tests PRIVATE cloak_dns_core GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(cloak_tests)
