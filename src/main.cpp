#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <CLI/CLI.hpp>

#include "core.hpp"
#include "path_util.hpp"

#ifdef _WIN32
#include <conio.h>
#include <io.h>
#ifndef NOMINMAX
#define NOMINMAX 1
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <shellapi.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

const std::string version = "1.0.4";
const std::string last_update = "2026/11/10";

namespace {
  bool stdin_is_terminal() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return ::isatty(STDIN_FILENO) != 0;
#endif
  }

  // 进度条只在真正的终端上画：管道/重定向时画进去只会污染日志。
  bool stderr_is_terminal() {
#ifdef _WIN32
    return _isatty(_fileno(stderr)) != 0;
#else
    return ::isatty(STDERR_FILENO) != 0;
#endif
  }

  std::string read_line_from_stdin() {
    std::string line;
    std::getline(std::cin, line);
    return line;
  }

  // 终端下不回显地读一行密码（每个字符打一个 *）；非终端（管道/重定向）直接读一行。
  std::string prompt_password(const std::string& prompt) {
    if (!stdin_is_terminal()) return read_line_from_stdin();

    std::cerr << prompt;
    std::cerr.flush();
    std::string password;

#ifdef _WIN32
    for (;;) {
      const int ch = _getch();
      if (ch == 0x00 || ch == 0xE0) { // 方向键等功能键，吞掉后面的扫描码
        _getch();
        continue;
      }
      if (ch == '\r' || ch == '\n') break;
      if (ch == 0x03) { // Ctrl+C
        std::cerr << "\n";
        std::exit(EXIT_FAILURE);
      }
      if (ch == 0x08 || ch == 0x7f) {
        if (!password.empty()) {
          password.pop_back();
          std::cerr << "\b \b";
        }
        continue;
      }
      if (ch >= 0x20) {
        password.push_back(static_cast<char>(ch));
        std::cerr << '*';
      }
    }
#else
    termios original{};
    termios hidden{};
    const bool restore = ::tcgetattr(STDIN_FILENO, &original) == 0;
    if (restore) {
      hidden = original;
      hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
      ::tcsetattr(STDIN_FILENO, TCSANOW, &hidden);
    }
    std::getline(std::cin, password);
    if (restore) ::tcsetattr(STDIN_FILENO, TCSANOW, &original);
#endif

    std::cerr << "\n";
    return password;
  }

#ifdef _WIN32
  std::string wide_to_utf8(const wchar_t* text) {
    if (text == nullptr || *text == L'\0') return std::string();
    const int length = ::WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 1) return std::string();
    std::string out(static_cast<size_t>(length - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), length - 1, nullptr, nullptr);
    return out;
  }

  std::wstring utf8_to_wide(const std::string& text) {
    if (text.empty()) return std::wstring();
    const int length = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) return std::wstring();
    std::wstring out(static_cast<size_t>(length), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), length);
    return out;
  }

  // main() 的 argv 已经被 CRT 用 CP_ACP 转成了窄字符：936/932 里没有的字符（比如 "・"）会变成 '?'，
  // 路径直接失效。所以这里丢掉 CRT 的 argv，改从 GetCommandLineW 取宽字符命令行自己拆参数，全程 UTF-8。
  std::vector<std::string> collect_arguments(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    int wide_argc = 0;
    LPWSTR* wide_argv = ::CommandLineToArgvW(::GetCommandLineW(), &wide_argc);
    if (wide_argv == nullptr) throw std::runtime_error("Failed to read the command line");

    std::vector<std::string> args;
    args.reserve(static_cast<size_t>(wide_argc > 0 ? wide_argc : 1));
    for (int i = 0; i < wide_argc; ++i) args.push_back(wide_to_utf8(wide_argv[i]));
    ::LocalFree(wide_argv);

    if (args.empty()) args.emplace_back("bs9p");
    return args;
  }

  void write_to_console(HANDLE handle, const std::string& text) {
    const std::wstring wide = utf8_to_wide(text);
    if (wide.empty()) return;
    DWORD written = 0;
    ::WriteConsoleW(handle, wide.data(), static_cast<DWORD>(wide.size()), &written, nullptr);
  }

  // 管道/重定向时按控制台代码页转码：Windows PowerShell 5.1 用 [Console]::OutputEncoding
  // 解码子进程输出，直接写 UTF-8 会显示乱码；没有控制台（纯重定向到文件）时保持 UTF-8。
  std::string utf8_to_console_code_page(const std::string& text, UINT code_page) {
    const std::wstring wide = utf8_to_wide(text);
    if (wide.empty()) return text;
    const int length = ::WideCharToMultiByte(code_page, 0, wide.data(), static_cast<int>(wide.size()),
                                             nullptr, 0, "?", nullptr);
    if (length <= 0) return text;
    std::string out(static_cast<size_t>(length), '\0');
    ::WideCharToMultiByte(code_page, 0, wide.data(), static_cast<int>(wide.size()), out.data(), length, "?", nullptr);
    return out;
  }

  void write_text(std::ostream& os, DWORD std_handle, const std::string& text) {
    if (text.empty()) return;
    const HANDLE handle = ::GetStdHandle(std_handle);
    DWORD mode = 0;
    if (handle != INVALID_HANDLE_VALUE && ::GetConsoleMode(handle, &mode) != 0) {
      write_to_console(handle, text); // 真控制台：宽字符直接写，任何字符都不会丢
      return;
    }
    const UINT code_page = ::GetConsoleOutputCP();
    if (code_page != 0 && code_page != CP_UTF8) {
      const std::string narrowed = utf8_to_console_code_page(text, code_page);
      os.write(narrowed.data(), static_cast<std::streamsize>(narrowed.size()));
      os.flush();
      return;
    }
    os.write(text.data(), static_cast<std::streamsize>(text.size()));
    os.flush();
  }

  void print_stdout(const std::string& text) { write_text(std::cout, STD_OUTPUT_HANDLE, text); }
  void print_stderr(const std::string& text) { write_text(std::cerr, STD_ERROR_HANDLE, text); }
#else
  std::vector<std::string> collect_arguments(int argc, char* argv[]) {
    std::vector<std::string> args;
    args.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i) args.emplace_back(argv[i]);
    return args;
  }

  void print_stdout(const std::string& text) { std::cout << text; std::cout.flush(); }
  void print_stderr(const std::string& text) { std::cerr << text; std::cerr.flush(); }
#endif
}

int main(int argc, char* argv[]) {

  CLI::App app{"Bs9p encode/decode tool"};
  app.name("bs9p");

  std::string mode;
  std::string password;
  std::string input;
  std::string output;
  uint64_t buffer_size = bs9::DEFAULT_BUFFER_SIZE;
  bool silent = false;
  bool password_stdin = false;

  app.add_option("mode", mode, "Mode: encode or decode")
    ->required()
    ->check(CLI::IsMember({"encode", "decode"}));
  app.add_option("password", password, "Password (omit it to be prompted without echo)");
  app.add_option("input", input, "Input file");
  app.add_option("-o,--out", output, "Output file, or an existing directory to place it in");
  app.add_option("-b,--buffer-size", buffer_size,
                 "IO buffer size in bytes, 65536 - 67108864 (default: " +
                   std::to_string(bs9::DEFAULT_BUFFER_SIZE) + ")")
    ->check(CLI::Range(static_cast<uint64_t>(bs9::MIN_BUFFER_SIZE),
                       static_cast<uint64_t>(bs9::MAX_BUFFER_SIZE)));
  app.add_flag("-s,--silent", silent, "Silent mode, no output");
  app.add_flag("--password-stdin", password_stdin, "Read the password from the first line of stdin");

  app.set_version_flag("-v,--version", "Bs9p tool version: " + version + " last_update: " + last_update);

  try {
    std::vector<std::string> args = collect_arguments(argc, argv);
    // CLI11 的 parse(std::vector<std::string>&) 约定：不含程序名，并且按倒序排列
    // （它从 vector 尾部依次取参数）。这里把 [程序名, 参数...] 转成 [参数N, ..., 参数1]。
    std::vector<std::string> cli_args;
    if (args.size() > 1) cli_args.assign(args.rbegin(), args.rend() - 1);
    app.parse(cli_args);
  } catch (const CLI::ParseError& e) {
    return app.exit(e);
  } catch (const std::exception& e) {
    print_stderr(std::string(" Error: ") + e.what() + "\n");
    return EXIT_FAILURE;
  }

  // 省略密码时只剩一个位置参数，CLI11 会先把它分给 password：这里还原成 input。
  // （--password-stdin 时同理：那个位置参数是 input。）
  if (input.empty() && !password.empty()) password.swap(input);

  int exit_code = EXIT_SUCCESS;

  try {
    if (input.empty()) throw std::invalid_argument("Input file is required.");
    if (password_stdin && !password.empty()) {
      throw std::invalid_argument("Password given both as an argument and via --password-stdin.");
    }

    const fs::path in = bs9::path_from_utf8(input);
    std::error_code ec;
    if (!fs::is_regular_file(in, ec)) {
      throw std::invalid_argument("Input file does not exist: " + input);
    }

    if (password_stdin) {
      password = read_line_from_stdin();
    } else if (password.empty()) {
      password = prompt_password("Password: ");
    }

    if (password.empty()) throw std::invalid_argument("Password must not be empty.");

    bs9::IoOptions io;
    io.buffer_size = bs9::clamp_buffer_size(buffer_size);
    if (!output.empty()) io.output = bs9::path_from_utf8(output);

    // 进度条画在 stderr：--silent 或非终端时不画，避免污染管道输出。
    bs9::Progress progress;
    if (!silent && stderr_is_terminal()) io.progress = &progress;

    if (mode == "encode") {

      const std::string out_name = bs9::encode_file(in, password, io);
      if (!silent) print_stdout(" Encode successfully: " + out_name + "\n");

    } else {

      const std::string out_name = bs9::decode_file(in, password, bs9::MEMORY_DECRYPT_LIMIT, io);
      if (!silent) print_stdout(" Decode successfully: " + out_name + "\n");

    }
  } catch (const std::ios_base::failure& e) {
    print_stderr(std::string(" Error: file I/O failed (") + e.what() + ")\n");
    exit_code = EXIT_FAILURE;
  } catch (const std::exception& e) {
    print_stderr(std::string(" Error: ") + e.what() + "\n");
    exit_code = EXIT_FAILURE;
  }

  // 密码是密钥材料，用完立刻擦除。
  bs9::cleanse_string(password);
  return exit_code;
}
