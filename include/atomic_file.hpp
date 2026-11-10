#ifndef _BS9P_ATOMIC_FILE
#define _BS9P_ATOMIC_FILE 1

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

#include "fileInfo.hpp"
#include "key.hpp"
#include "path_util.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX 1
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace bs9 {
  // 结果文件一律「先写同目录临时文件 -> 落盘 -> 原子改名」：
  // 进程被杀、断电、磁盘写满时，目标路径要么不存在，要么是完整文件，
  // 永远不会留下半个密文 / 半个明文，也不会破坏输入文件。
  namespace detail {
    inline std::string random_hex() {
      uint8_t bytes[8] = {};
      bs9::random_bytes(bytes, sizeof(bytes));
      static constexpr char hex[] = "0123456789abcdef";
      std::string out;
      out.reserve(sizeof(bytes) * 2);
      for (const uint8_t byte : bytes) {
        out.push_back(hex[byte >> 4]);
        out.push_back(hex[byte & 0x0f]);
      }
      return out;
    }

    // 把已写入的文件内容刷到物理介质（不是只刷到页缓存）。
    inline void sync_file(const fs::path& path) {
#ifdef _WIN32
      HANDLE handle = ::CreateFileW(path.c_str(), GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (handle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Failed to open file for flushing: " + bs9::path_to_utf8(path));
      }
      const BOOL flushed = ::FlushFileBuffers(handle);
      ::CloseHandle(handle);
      if (flushed == 0) throw std::runtime_error("Failed to flush file to disk: " + bs9::path_to_utf8(path));
#else
      const int fd = ::open(path.c_str(), O_RDONLY);
      if (fd < 0) throw std::runtime_error("Failed to open file for flushing: " + bs9::path_to_utf8(path));
      const int rc = ::fsync(fd);
      ::close(fd);
      if (rc != 0) throw std::runtime_error("Failed to flush file to disk: " + bs9::path_to_utf8(path));
#endif
    }

    // 改名落位，并且「不覆盖已有文件」。临时文件与目标同目录，改名不会跨卷。
    inline void move_into_place(const fs::path& from, const fs::path& to) {
#ifdef _WIN32
      // 不带 MOVEFILE_REPLACE_EXISTING：目标已存在时失败，不存在时原子改名。
      if (::MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_WRITE_THROUGH) == 0) {
        const DWORD error = ::GetLastError();
        if (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS) {
          throw std::runtime_error("File already exists: " + bs9::path_to_utf8(to));
        }
        throw std::runtime_error("Failed to move temporary file into place: " + bs9::path_to_utf8(to) +
                                 " (Windows error " + std::to_string(error) + ")");
      }
#else
      // link(2) 在目标已存在时返回 EEXIST，天然没有「先检查再改名」的竞争窗口。
      if (::link(from.c_str(), to.c_str()) == 0) {
        ::unlink(from.c_str());
      } else if (errno == EEXIST) {
        throw std::runtime_error("File already exists: " + bs9::path_to_utf8(to));
      } else if (errno == EPERM || errno == EOPNOTSUPP || errno == EXDEV || errno == ENOTSUP) {
        // 文件系统不支持硬链接（FAT/exFAT、部分网络盘）：退回改名。
        std::error_code ec;
        fs::rename(from, to, ec);
        if (ec) throw std::runtime_error("Failed to move temporary file into place: " + bs9::path_to_utf8(to) + " (" +
                                         ec.message() + ")");
      } else {
        throw std::runtime_error("Failed to move temporary file into place: " + bs9::path_to_utf8(to) + " (" +
                                 std::strerror(errno) + ")");
      }
#endif
    }

#ifndef _WIN32
    // 让「改名」本身也持久化；Windows 的 MOVEFILE_WRITE_THROUGH 已覆盖这一点。
    inline void sync_directory(const fs::path& directory) {
      const fs::path dir = directory.empty() ? fs::path(".") : directory;
      const int fd = ::open(dir.c_str(), O_RDONLY);
      if (fd < 0) return;
      ::fsync(fd);
      ::close(fd);
    }
#endif
  }

  class AtomicOutput {
    fs::path target_;
    fs::path temp_;
    std::ofstream ofs_;
    bool committed_ = false;

  public:
    explicit AtomicOutput(fs::path target) : target_(std::move(target)) {
      fs::path directory = target_.parent_path();
      if (directory.empty()) directory = fs::path(".");

      // 临时文件名 = 目标文件名 + ".tmp-" + 随机后缀：用 UTF-8 中转，避免 ACP 转换把日文名变成 '?'。
      const std::string base = bs9::path_to_utf8(target_.filename()) + ".tmp-";
      temp_ = directory / bs9::path_from_utf8(base + bs9::detail::random_hex());
      for (int attempt = 0; attempt < 8; ++attempt) {
        std::error_code ec;
        if (!fs::exists(temp_, ec)) break;
        temp_ = directory / bs9::path_from_utf8(base + bs9::detail::random_hex());
      }

      ofs_.open(temp_, std::ios::binary | std::ios::trunc);
      if (!ofs_.is_open()) {
        throw std::runtime_error("Failed to create temporary output file: " + bs9::path_to_utf8(temp_));
      }
      // 之后任何写失败（磁盘满、权限、句柄失效）都会抛异常，而不是被静默忽略。
      ofs_.exceptions(std::ios::failbit | std::ios::badbit);
    }

    AtomicOutput(const AtomicOutput&) = delete;
    AtomicOutput& operator=(const AtomicOutput&) = delete;

    ~AtomicOutput() {
      try {
        if (ofs_.is_open()) {
          ofs_.exceptions(std::ios::goodbit); // 析构里绝不能抛
          ofs_.close();
        }
      } catch (...) {
      }
      if (!committed_) {
        std::error_code ec;
        fs::remove(temp_, ec);
      }
    }

    std::ofstream& stream() { return ofs_; }

    // 刷盘 + 原子落位。失败时抛异常，析构会删掉临时文件，目标路径保持不变。
    void commit() {
      ofs_.flush();
      ofs_.close();
      bs9::detail::sync_file(temp_);
      bs9::detail::move_into_place(temp_, target_);
#ifndef _WIN32
      bs9::detail::sync_directory(target_.parent_path());
#endif
      committed_ = true;
    }
  };
}

#endif
