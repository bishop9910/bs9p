#include <filesystem>
#include <string>

#include "path_util.hpp"

#ifndef _BS9_FILEINFO
#define _BS9_FILEINFO 1

namespace bs9 {
  namespace fs = std::filesystem;

  struct FileInfo {
    std::string stem;      // file name without extension: "report"（UTF-8）
    std::string extension; // extension with dot: ".pdf"（UTF-8）
    std::string filename;  // full file name: "report.pdf"（UTF-8）
    fs::path parent_path;  // parent directory: "/home/user"
    fs::path pure_path;    // full path without extension: "/home/user/report"
  };

  // header-only 工程里必须 inline：否则每个包含本头的翻译单元都会产生一份定义。
  // 字符串字段统一转成 UTF-8：这些值会写进文件头 / 打印到终端，用 ACP 转换会丢字符。
  inline FileInfo parse_file(const fs::path& filepath) {
    FileInfo info;
    info.stem = bs9::path_to_utf8(filepath.stem());
    info.extension = bs9::path_to_utf8(filepath.extension());
    info.filename = bs9::path_to_utf8(filepath.filename());
    info.parent_path = filepath.parent_path();
    info.pure_path = info.parent_path / filepath.stem();
    return info;
  }

}

#endif
