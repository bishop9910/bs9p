cmake_minimum_required(VERSION 3.31)

project(bs9p)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

include(CTest)

# 源码是 UTF-8（含中文注释），MSVC 默认按系统代码页解析会破坏 token（C4819 之后的语法错误）
if (MSVC)
    add_compile_options(/utf-8)
endif()

add_subdirectory(src)

if (BUILD_TESTING)
    add_subdirectory(tests)
endif()

if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()