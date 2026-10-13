#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <stdexcept>

#include "fileInfo.hpp"
#include "magic.hpp"
#include "data_dict.hpp"
#include "convert.hpp"
#include "key.hpp"

#ifndef _BS9P_CORE
#define _BS9P_CORE 1

namespace bs9 {
  inline constexpr size_t SALT_LEN = 16;
  inline constexpr size_t NONCE_LEN = 12;
  inline constexpr size_t TAG_LEN = 32;
  inline constexpr uint32_t PBKDF2_ITERATIONS = 200000;
  inline constexpr uint32_t MAX_ITERATIONS = 10000000;
  inline constexpr size_t BUFFER_SIZE = 1 << 16;

  struct Header {
    uint32_t iterations = 0;
    uint8_t salt[SALT_LEN] = {};
    uint8_t nonce[NONCE_LEN] = {};
    std::string extension;
    uint64_t plain_len = 0;
    uint64_t size = 0;
    std::vector<uint8_t> raw;
  };

  inline Header make_header(const std::string& extension, uint64_t plain_len) {
    if (extension.size() > 0xffff) throw std::runtime_error("Extension is too long");

    bs9::Header header;
    header.iterations = bs9::PBKDF2_ITERATIONS;
    header.extension = extension;
    header.plain_len = plain_len;
    bs9::random_bytes(header.salt, SALT_LEN);
    bs9::random_bytes(header.nonce, NONCE_LEN);

    bs9::append_uint64(header.raw, bs9::build_magic(bs9::magic_buf));
    bs9::append_uint32(header.raw, header.iterations);
    bs9::append_bytes(header.raw, header.salt, SALT_LEN);
    bs9::append_bytes(header.raw, header.nonce, NONCE_LEN);
    bs9::append_uint16(header.raw, static_cast<uint16_t>(extension.size()));
    bs9::append_bytes(header.raw, reinterpret_cast<const uint8_t*>(extension.data()), extension.size());
    bs9::append_uint64(header.raw, plain_len);

    header.size = header.raw.size();
    return header;
  }

  inline Header read_header(std::istream& is) {
    bs9::Header header;
    const size_t fixed_len = 8 + 4 + SALT_LEN + NONCE_LEN;
    header.raw.resize(fixed_len);
    bs9::read_exact(is, header.raw.data(), fixed_len);

    if (bs9::load_uint64(header.raw.data()) != bs9::build_magic(bs9::magic_buf)) {
      throw std::runtime_error("Magic mismatch");
    }

    header.iterations = bs9::load_uint32(header.raw.data() + 8);
    if (header.iterations == 0 || header.iterations > bs9::MAX_ITERATIONS) {
      throw std::runtime_error("Invalid iteration count");
    }

    std::memcpy(header.salt, header.raw.data() + 12, SALT_LEN);
    std::memcpy(header.nonce, header.raw.data() + 12 + SALT_LEN, NONCE_LEN);

    uint8_t ext_len_buf[2];
    bs9::read_exact(is, ext_len_buf, 2);
    bs9::append_bytes(header.raw, ext_len_buf, 2);

    std::vector<uint8_t> extension(bs9::load_uint16(ext_len_buf));
    bs9::read_exact(is, extension.data(), extension.size());
    bs9::append_bytes(header.raw, extension.data(), extension.size());
    header.extension.assign(extension.begin(), extension.end());

    uint8_t len_buf[8];
    bs9::read_exact(is, len_buf, 8);
    bs9::append_bytes(header.raw, len_buf, 8);
    header.plain_len = bs9::load_uint64(len_buf);

    header.size = header.raw.size();
    return header;
  }

  inline void update_mac(bs9::HmacSha256& mac, std::istream& is, uint64_t length) {
    std::vector<uint8_t> buffer(bs9::BUFFER_SIZE);
    while (length > 0) {
      const size_t chunk = static_cast<size_t>(std::min<uint64_t>(length, buffer.size()));
      bs9::read_exact(is, buffer.data(), chunk);
      mac.update(buffer.data(), chunk);
      length -= chunk;
    }
  }

  inline void verify_mac(std::istream& is, const bs9::Header& header, const uint8_t* mac_key) {
    bs9::HmacSha256 mac(mac_key, bs9::TAG_LEN);
    mac.update(header.raw.data(), header.raw.size());
    bs9::update_mac(mac, is, header.plain_len);

    uint8_t stored[TAG_LEN];
    bs9::read_exact(is, stored, TAG_LEN);

    const bs9::Digest computed = mac.final();
    if (!bs9::equal_constant_time(stored, computed.data(), computed.size())) {
      throw std::runtime_error("Wrong password or corrupted file");
    }
  }

  inline uint8_t encode(const uint8_t& data_byte) {
    return bs9::data_dict[data_byte];
  }

  inline std::string encode_file(const fs::path& in, const std::string& password) {
    const bs9::FileInfo info = bs9::parse_file(in);

    const std::string out = info.pure_path.string() + ".bs9p";
    if (fs::exists(out)) throw std::runtime_error("File already exists");

    std::ifstream ifs(in, std::ios::binary);
    if (!ifs) throw std::runtime_error("Failed to open input file.");
    std::ofstream ofs(out, std::ios::binary);
    if (!ofs) throw std::runtime_error("Failed to open output file.");

    const bs9::Header header = bs9::make_header(info.extension, static_cast<uint64_t>(fs::file_size(in)));
    const bs9::KeySet keys = bs9::derive_keys(password, header.salt, SALT_LEN, header.iterations);
    bs9::init_data_dict(keys.dict.data());

    bs9::HmacSha256 mac(keys.mac.data(), keys.mac.size());
    mac.update(header.raw.data(), header.raw.size());
    ofs.write(reinterpret_cast<const char*>(header.raw.data()), static_cast<std::streamsize>(header.raw.size()));

    std::vector<uint8_t> buffer(bs9::BUFFER_SIZE);
    bs9::ChaCha20 stream(keys.stream.data(), header.nonce, 0);

    uint64_t left = header.plain_len;
    while (left > 0) {
      const size_t chunk = static_cast<size_t>(std::min<uint64_t>(left, buffer.size()));
      bs9::read_exact(ifs, buffer.data(), chunk);

      for (size_t i = 0; i < chunk; ++i) buffer[i] = bs9::encode(buffer[i]);
      stream.xor_data(buffer.data(), chunk);
      mac.update(buffer.data(), chunk);

      ofs.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(chunk));
      left -= chunk;
    }

    const bs9::Digest tag = mac.final();
    ofs.write(reinterpret_cast<const char*>(tag.data()), static_cast<std::streamsize>(tag.size()));

    return out;
  }

  inline uint8_t decode(const uint8_t& data_byte) {
    return bs9::reverse_dict[data_byte];
  }

  inline std::string decode_file(const fs::path& in, const std::string& password) {
    std::ifstream ifs(in, std::ios::binary);
    if (!ifs) throw std::runtime_error("Failed to open input file.");

    const bs9::Header header = bs9::read_header(ifs);

    const bs9::FileInfo info = bs9::parse_file(in);
    const std::string out = info.pure_path.string() + header.extension;
    if (fs::exists(out)) throw std::runtime_error("File already exists");

    const bs9::KeySet keys = bs9::derive_keys(password, header.salt, SALT_LEN, header.iterations);
    bs9::init_data_dict(keys.dict.data());

    bs9::verify_mac(ifs, header, keys.mac.data());

    ifs.clear();
    ifs.seekg(static_cast<std::streamoff>(header.size));

    std::ofstream ofs(out, std::ios::binary);
    if (!ofs) throw std::runtime_error("Failed to open output file.");

    std::vector<uint8_t> buffer(bs9::BUFFER_SIZE);
    bs9::ChaCha20 stream(keys.stream.data(), header.nonce, 0);

    uint64_t left = header.plain_len;
    while (left > 0) {
      const size_t chunk = static_cast<size_t>(std::min<uint64_t>(left, buffer.size()));
      bs9::read_exact(ifs, buffer.data(), chunk);
      stream.xor_data(buffer.data(), chunk);

      for (size_t i = 0; i < chunk; ++i) buffer[i] = bs9::decode(buffer[i]);

      ofs.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(chunk));
      left -= chunk;
    }

    return out;
  }
}

#endif
