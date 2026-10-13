set(SOURCES 
  main.cpp
  res/res.rc
)

add_executable(bs9p 
  ${SOURCES}
)

target_include_directories(bs9p PUBLIC ${PROJECT_SOURCE_DIR}/include)

find_package(CLI11 CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

target_link_libraries(bs9p PRIVATE
  CLI11::CLI11
  OpenSSL::Crypto
)