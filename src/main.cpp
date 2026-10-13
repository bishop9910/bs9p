#include <iostream>
#include <filesystem>
#include <cstdint>
#include <string>

#include <CLI/CLI.hpp>

#include "core.hpp"

namespace fs = std::filesystem;

const std::string version = "2.0.0.2";
const std::string last_update = "2026/10/13";

int main(int argc, char* argv[]) {

  CLI::App app{"Bs9p encode/decode tool"};

  std::string mode;
  std::string password;
  std::string input;
  bool silent = false;

  app.add_option("mode", mode, "Mode: encode or decode")
    ->required()
    ->check(CLI::IsMember({"encode", "decode"}));
  app.add_option("password", password, "Password")->required();
  app.add_option("input", input, "Input file")->required();
  app.add_flag("-s,--silent", silent, "Silent mode, no output");

  app.set_version_flag("-v,--version", "Bs9p tool version: " + version + " last_update: " + last_update);

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError& e) {
    return app.exit(e);
  }

  const fs::path in = input;

  try {

    if (password.empty()) throw std::invalid_argument("Password must not be empty.");
    if (!fs::exists(in) || !fs::is_regular_file(in)) throw std::invalid_argument("Input file does not exist.");

    if (mode == "encode") {

      std::string out = bs9::encode_file(in, password);
      if(!silent) std::cout << " Encode successfully: " << out << "\n";

    } else {

      std::string out = bs9::decode_file(in, password);
      if(!silent) std::cout << " Decode successfully: " << out << "\n";

    }
  } catch (const std::exception& e) {
    std::cerr << " Error: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
