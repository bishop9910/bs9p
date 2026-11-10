#include <filesystem>
#include <string>

#ifndef _BS9_PATH_UTIL
#define _BS9_PATH_UTIL 1

namespace bs9 {
  namespace fs = std::filesystem;

  // 程序内部一律用 UTF-8 保存路径文本：
  //  - Windows：宽字符 <-> UTF-8 显式转换，绕开 CP_ACP（否则 "・"、部分假名之类
  //    在 936/932 里没有映射的字符会被替换成 '?'，路径直接失效）；
  //  - POSIX：路径本来就是字节串，原样透传，不做任何转码。
  inline fs::path path_from_utf8(const std::string& text) {
#ifdef _WIN32
    return fs::u8path(text);
#else
    return fs::path(text);
#endif
  }

  inline std::string path_to_utf8(const fs::path& path) {
#ifdef _WIN32
    return path.u8string();
#else
    return path.string();
#endif
  }
}

#endif
