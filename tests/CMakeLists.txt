find_package(OpenSSL REQUIRED)

add_executable(bs9p_tests
  test_bs9p.cpp
)

target_include_directories(bs9p_tests PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(bs9p_tests PRIVATE OpenSSL::Crypto)

if (MSVC)
  target_compile_options(bs9p_tests PRIVATE /W4)
else()
  target_compile_options(bs9p_tests PRIVATE -Wall -Wextra)
endif()

add_test(NAME bs9p_tests COMMAND bs9p_tests)
