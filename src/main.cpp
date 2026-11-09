#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>

#include <CLI/CLI.hpp>

#include "core.hpp"

#ifdef _WIN32
#include <conio.h>
#include <io.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

const std::string version = "1.0.3";
const std::string last_update = "2026/11/09";

namespace {
  bool stdin_is_terminal() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return ::isatty(STDIN_FILENO) != 0;
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
}

int main(int argc, char* argv[]) {

  CLI::App app{"Bs9p encode/decode tool"};

  std::string mode;
  std::string password;
  std::string input;
  bool silent = false;
  bool password_stdin = false;

  app.add_option("mode", mode, "Mode: encode or decode")
    ->required()
    ->check(CLI::IsMember({"encode", "decode"}));
  app.add_option("password", password, "Password (omit it to be prompted without echo)");
  app.add_option("input", input, "Input file");
  app.add_flag("-s,--silent", silent, "Silent mode, no output");
  app.add_flag("--password-stdin", password_stdin, "Read the password from the first line of stdin");

  app.set_version_flag("-v,--version", "Bs9p tool version: " + version + " last_update: " + last_update);

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError& e) {
    return app.exit(e);
  }

  // 省略密码时只剩一个位置参数，CLI11 会先把它分给 password：这里还原成 input。
  // （--password-stdin 时那个位置参数本来就一定是 input。）
  if (input.empty() && !password.empty()) {
    std::error_code ec;
    if (password_stdin || fs::exists(fs::path(password), ec)) {
      input = password;
      password.clear();
    }
  }

  int exit_code = EXIT_SUCCESS;

  try {
    if (input.empty()) throw std::invalid_argument("Input file is required.");
    if (password_stdin && !password.empty()) {
      throw std::invalid_argument("Password given both as an argument and via --password-stdin.");
    }

    const fs::path in = input;
    if (!fs::exists(in) || !fs::is_regular_file(in)) {
      throw std::invalid_argument("Input file does not exist: " + in.string());
    }

    if (password_stdin) {
      password = read_line_from_stdin();
    } else if (password.empty()) {
      password = prompt_password("Password: ");
    }

    if (password.empty()) throw std::invalid_argument("Password must not be empty.");

    if (mode == "encode") {

      std::string out = bs9::encode_file(in, password);
      if (!silent) std::cout << " Encode successfully: " << out << "\n";

    } else {

      std::string out = bs9::decode_file(in, password);
      if (!silent) std::cout << " Decode successfully: " << out << "\n";

    }
  } catch (const std::ios_base::failure& e) {
    std::cerr << " Error: file I/O failed (" << e.what() << ")\n";
    exit_code = EXIT_FAILURE;
  } catch (const std::exception& e) {
    std::cerr << " Error: " << e.what() << "\n";
    exit_code = EXIT_FAILURE;
  }

  // 密码是密钥材料，用完立刻擦除。
  bs9::cleanse_string(password);
  return exit_code;
}
