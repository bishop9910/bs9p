#include <string>
#include <filesystem>

#ifndef _BS9_FILEINFO
#define _BS9_FILEINFO 1

namespace bs9 {
  namespace fs = std::filesystem;

  struct FileInfo {
    std::string stem;      // file name without extension: "report"
    std::string extension; // extension with dot: ".pdf"
    std::string filename;  // full file name: "report.pdf"
    fs::path parent_path;  // parent directory: "/home/user"
    fs::path pure_path;    // full path without extension: "/home/user/report"
  };

  FileInfo parse_file(const fs::path& filepath) {
    FileInfo info;
    info.stem = filepath.stem().string();
    info.extension = filepath.extension().string();
    info.filename = filepath.filename().string();
    info.parent_path = filepath.parent_path();
    info.pure_path = info.parent_path / info.stem;
    return info;
  }

}

#endif