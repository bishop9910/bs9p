#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include "atomic_file.hpp"
#include "convert.hpp"
#include "data_dict.hpp"
#include "fileInfo.hpp"
#include "key.hpp"
#include "magic.hpp"
#include "progress.hpp"

#ifndef _BS9P_CORE
#define _BS9P_CORE 1

namespace bs9 {
  inline constexpr size_t SALT_LEN = 16;
  inline constexpr size_t NONCE_LEN = 12;
  inline constexpr size_t TAG_LEN = 32;
  inline constexpr uint32_t PBKDF2_ITERATIONS = 200000;
  inline constexpr uint32_t MAX_ITERATIONS = 10000000;

  // IO 缓冲：默认取 64 KiB。实测在机械盘（尤其 SMR）上，缓冲越大反而越慢——
  // 大块写入把写回打散，同盘边读边写时吞吐从 ~85 MiB/s 掉到 ~37 MiB/s；
  // 在 SSD 上 1 MiB 只比 64 KiB 快约 7%，不值得为此牺牲机械盘。需要时用 --buffer-size 覆盖。
  // 64 KiB 是下限（避免破坏顺序读写的批处理），64 MiB 是上限（防止有人给出离谱值把内存吃光）。
  inline constexpr size_t MIN_BUFFER_SIZE = 64 * 1024;
  inline constexpr size_t DEFAULT_BUFFER_SIZE = MIN_BUFFER_SIZE;
  inline constexpr size_t MAX_BUFFER_SIZE = 64 * 1024 * 1024;
  // 兼容旧名字：内部辅助函数（update_mac 等）仍按这个尺寸分配。
  inline constexpr size_t BUFFER_SIZE = MIN_BUFFER_SIZE;

  // 解密分两条路径：明文不超过该阈值时先解到内存、验完 MAC 再落盘（一遍 IO 且验证前不落盘）；
  // 超过阈值则边解密边写临时文件（一遍 IO，但验证前明文已落盘，失败时删临时文件）。
  inline constexpr uint64_t MEMORY_DECRYPT_LIMIT = 128ull * 1024ull * 1024ull;
  inline constexpr size_t MAX_EXTENSION_LEN = 255;

  // 加解密共用的 IO 选项：缓冲大小、进度条、输出位置。
  struct IoOptions {
    size_t buffer_size = DEFAULT_BUFFER_SIZE;
    bs9::Progress* progress = nullptr;
    // 空表示沿用默认命名（in + ".bs9p" / 去掉 .bs9p）；给目录则用默认文件名放进该目录。
    fs::path output;
  };

  inline size_t clamp_buffer_size(uint64_t requested) {
    if (requested < MIN_BUFFER_SIZE) return MIN_BUFFER_SIZE;
    if (requested > MAX_BUFFER_SIZE) return MAX_BUFFER_SIZE;
    return static_cast<size_t>(requested);
  }

  inline fs::path resolve_output(const fs::path& requested, const fs::path& fallback) {
    if (requested.empty()) return fallback;
    std::error_code ec;
    if (fs::is_directory(requested, ec)) return requested / fallback.filename();
    return requested;
  }

  struct Header {
    uint32_t iterations = 0;
    uint8_t salt[SALT_LEN] = {};
    uint8_t nonce[NONCE_LEN] = {};
    std::string extension;
    uint64_t plain_len = 0;
    uint64_t size = 0;
    std::vector<uint8_t> raw;
  };

  // 扩展名会参与拼出输出路径，而文件头在验 MAC 之前是不可信的：
  // 必须挡住 "/" "\\" 之类的分隔符，否则一个恶意文件头能把输出（以及临时文件）写到目录外。
  inline void validate_extension(const std::string& extension) {
    if (extension.empty()) return;
    if (extension.size() > MAX_EXTENSION_LEN) throw std::runtime_error("Stored extension is too long");
    if (extension[0] != '.') throw std::runtime_error("Stored extension does not start with a dot");

    for (const char raw : extension) {
      const unsigned char c = static_cast<unsigned char>(raw);
      if (c < 0x20 || c == 0x7f) throw std::runtime_error("Stored extension contains a control character");
      switch (c) {
        case '/':
        case '\\':
        case ':':
        case '*':
        case '?':
        case '"':
        case '<':
        case '>':
        case '|':
          throw std::runtime_error("Stored extension contains a path separator or reserved character");
        default:
          break;
      }
    }
  }

  inline Header make_header(const std::string& extension, uint64_t plain_len) {
    bs9::validate_extension(extension);
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
      throw std::runtime_error("Magic mismatch: not a bs9p file, or it was made by an incompatible version");
    }

    header.iterations = bs9::load_uint32(header.raw.data() + 8);
    if (header.iterations == 0 || header.iterations > bs9::MAX_ITERATIONS) {
      throw std::runtime_error("Invalid iteration count in header");
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
    bs9::validate_extension(header.extension);

    uint8_t len_buf[8];
    bs9::read_exact(is, len_buf, 8);
    bs9::append_bytes(header.raw, len_buf, 8);
    header.plain_len = bs9::load_uint64(len_buf);

    header.size = header.raw.size();
    return header;
  }

  // 头里的 plain_len 决定要读多少密文，不能直接信：
  // 一是长度必须落在 ChaCha20 计数器能覆盖的范围内，二是文件总长必须与头完全吻合。
  inline void validate_layout(const Header& header, uint64_t file_size) {
    if (header.plain_len > bs9::chacha_max_bytes(0)) {
      throw std::runtime_error("Invalid plaintext length in header: too large for ChaCha20");
    }
    const uint64_t expected = header.size + header.plain_len + TAG_LEN;
    if (expected != file_size) {
      throw std::runtime_error("File size mismatch: header expects " + std::to_string(expected) +
                               " bytes, file has " + std::to_string(file_size));
    }
  }

  // 防止解密输出路径正好是输入路径（例如头里存的扩展名就是 ".bs9p"）而把密文覆盖掉。
  inline bool same_file(const fs::path& left, const fs::path& right) {
    std::error_code ec;
    fs::path a = fs::weakly_canonical(left, ec);
    if (ec) {
      a = fs::absolute(left, ec);
      if (ec) return false;
    }
    fs::path b = fs::weakly_canonical(right, ec);
    if (ec) {
      b = fs::absolute(right, ec);
      if (ec) return false;
    }
    return a == b;
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

  inline std::string encode_file(const fs::path& in, const std::string& password,
                                 const bs9::IoOptions& io = {}) {
    // 密文名就是「完整文件名 + .bs9p」：report.pdf → report.pdf.bs9p。
    fs::path out = in;
    out += ".bs9p";
    out = bs9::resolve_output(io.output, out);

    if (bs9::same_file(in, out)) {
      throw std::runtime_error("Output file would overwrite the input file: " + bs9::path_to_utf8(out));
    }
    if (fs::exists(out)) throw std::runtime_error("File already exists: " + bs9::path_to_utf8(out));

    std::error_code ec;
    const uint64_t plain_len = fs::file_size(in, ec);
    if (ec) throw std::runtime_error("Failed to read input file size: " + bs9::path_to_utf8(in) + " (" + ec.message() + ")");
    if (plain_len > bs9::chacha_max_bytes(0)) {
      throw std::runtime_error("File is too large for ChaCha20 (limit is 256 GiB): " + bs9::path_to_utf8(in));
    }

    std::ifstream ifs(in, std::ios::binary);
    if (!ifs) throw std::runtime_error("Failed to open input file: " + bs9::path_to_utf8(in));
    ifs.exceptions(std::ios::badbit);

    const bs9::Header header = bs9::make_header(bs9::parse_file(in).extension, plain_len);
    bs9::KeySet keys = bs9::derive_keys(password, header.salt, SALT_LEN, header.iterations);
    const bs9::DataDict dict(keys.dict.data());

    bs9::HmacSha256 mac(keys.mac.data(), keys.mac.size());
    mac.update(header.raw.data(), header.raw.size());

    bs9::AtomicOutput output(out);
    std::ostream& ofs = output.stream();
    ofs.write(reinterpret_cast<const char*>(header.raw.data()), static_cast<std::streamsize>(header.raw.size()));

    bs9::ChaCha20 stream(keys.stream.data(), header.nonce, 0);
    std::vector<uint8_t> buffer(bs9::clamp_buffer_size(io.buffer_size));
    bs9::Progress* const progress =
        (io.progress != nullptr && header.plain_len >= bs9::PROGRESS_MIN_BYTES) ? io.progress : nullptr;
    if (progress != nullptr) progress->begin(header.plain_len, "encrypting");

    uint64_t left = header.plain_len;
    uint64_t done = 0;
    while (left > 0) {
      const size_t chunk = static_cast<size_t>(std::min<uint64_t>(left, buffer.size()));
      bs9::read_exact(ifs, buffer.data(), chunk);

      for (size_t i = 0; i < chunk; ++i) buffer[i] = dict.encode(buffer[i]);
      stream.xor_data(buffer.data(), chunk);
      mac.update(buffer.data(), chunk);

      ofs.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(chunk));
      left -= chunk;
      done += chunk;
      if (progress != nullptr) progress->update(done);
    }
    if (progress != nullptr) progress->finish();

    const bs9::Digest tag = mac.final();
    ofs.write(reinterpret_cast<const char*>(tag.data()), static_cast<std::streamsize>(tag.size()));

    output.commit();
    return bs9::path_to_utf8(out);
  }

  inline std::string decode_file(const fs::path& in, const std::string& password,
                                 uint64_t memory_limit = bs9::MEMORY_DECRYPT_LIMIT,
                                 const bs9::IoOptions& io = {}) {
    std::ifstream ifs(in, std::ios::binary);
    if (!ifs) throw std::runtime_error("Failed to open input file: " + bs9::path_to_utf8(in));
    ifs.exceptions(std::ios::badbit);

    const bs9::Header header = bs9::read_header(ifs);

    std::error_code ec;
    const uint64_t file_size = fs::file_size(in, ec);
    if (ec) throw std::runtime_error("Failed to read input file size: " + bs9::path_to_utf8(in) + " (" + ec.message() + ")");
    bs9::validate_layout(header, file_size);

    // 解密目标名：密文名就是「原名 + .bs9p」，所以直接去掉末尾的 .bs9p 即还原原文件名。
    // 若密文被改过名（没有 .bs9p 后缀），退回头里记录的扩展名来重建；去掉 .bs9p 后名字
    // 里还没有原始扩展名的（旧版本生成的 sample.pdf → sample.bs9p），也按头里的扩展名补回。
    std::string out_name = bs9::path_to_utf8(in);
    static constexpr const char cipher_suffix[] = ".bs9p";
    constexpr size_t suffix_len = sizeof(cipher_suffix) - 1;
    if (out_name.size() > suffix_len &&
        out_name.compare(out_name.size() - suffix_len, suffix_len, cipher_suffix) == 0) {
      out_name.resize(out_name.size() - suffix_len);
    } else {
      out_name = bs9::path_to_utf8(bs9::parse_file(in).pure_path);
    }
    const std::string& ext = header.extension;
    if (!ext.empty() &&
        (out_name.size() < ext.size() ||
         out_name.compare(out_name.size() - ext.size(), ext.size(), ext) != 0)) {
      out_name += ext;
    }
    const fs::path out = bs9::resolve_output(io.output, bs9::path_from_utf8(out_name));

    if (bs9::same_file(in, out)) {
      throw std::runtime_error("Output file would overwrite the input file: " + bs9::path_to_utf8(out));
    }
    if (fs::exists(out)) throw std::runtime_error("File already exists: " + bs9::path_to_utf8(out));

    bs9::KeySet keys = bs9::derive_keys(password, header.salt, SALT_LEN, header.iterations);
    const bs9::DataDict dict(keys.dict.data());

    bs9::HmacSha256 mac(keys.mac.data(), keys.mac.size());
    mac.update(header.raw.data(), header.raw.size());

    bs9::Progress* const progress =
        (io.progress != nullptr && header.plain_len >= bs9::PROGRESS_MIN_BYTES) ? io.progress : nullptr;
    if (progress != nullptr) progress->begin(header.plain_len, "decrypting");

    // 小文件：先整体解密到内存，验完 MAC 才创建输出文件，失败时磁盘上不留任何明文。
    if (header.plain_len <= memory_limit) {
      std::vector<uint8_t> data(static_cast<size_t>(header.plain_len));
      const bs9::CleanseGuard plain_guard(data.data(), data.size());

      if (!data.empty()) {
        const size_t step = bs9::clamp_buffer_size(io.buffer_size);
        uint64_t done = 0;
        while (done < data.size()) {
          const size_t chunk = std::min<size_t>(step, data.size() - static_cast<size_t>(done));
          bs9::read_exact(ifs, data.data() + done, chunk);
          mac.update(data.data() + done, chunk); // MAC 覆盖密文，必须在解密之前
          done += chunk;
          if (progress != nullptr) progress->update(done);
        }
      }

      uint8_t stored[TAG_LEN];
      bs9::read_exact(ifs, stored, TAG_LEN);
      const bs9::Digest computed = mac.final();
      if (!bs9::equal_constant_time(stored, computed.data(), computed.size())) {
        throw std::runtime_error("Wrong password or corrupted file");
      }

      if (!data.empty()) {
        bs9::ChaCha20 stream(keys.stream.data(), header.nonce, 0);
        stream.xor_data(data.data(), data.size());
        for (size_t i = 0; i < data.size(); ++i) data[i] = dict.decode(data[i]);
      }
      if (progress != nullptr) progress->finish();

      bs9::AtomicOutput output(out);
      if (!data.empty()) {
        output.stream().write(reinterpret_cast<const char*>(data.data()),
                              static_cast<std::streamsize>(data.size()));
      }
      output.commit();
      return bs9::path_to_utf8(out);
    }

    // 大文件：边解密边写临时文件，MAC 不符时抛异常，临时文件由 AtomicOutput 析构删除。
    bs9::AtomicOutput output(out);
    std::ostream& ofs = output.stream();

    bs9::ChaCha20 stream(keys.stream.data(), header.nonce, 0);
    std::vector<uint8_t> buffer(bs9::clamp_buffer_size(io.buffer_size));

    uint64_t left = header.plain_len;
    uint64_t done = 0;
    while (left > 0) {
      const size_t chunk = static_cast<size_t>(std::min<uint64_t>(left, buffer.size()));
      bs9::read_exact(ifs, buffer.data(), chunk);
      mac.update(buffer.data(), chunk); // 先吃密文，再解密
      stream.xor_data(buffer.data(), chunk);
      for (size_t i = 0; i < chunk; ++i) buffer[i] = dict.decode(buffer[i]);

      ofs.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(chunk));
      left -= chunk;
      done += chunk;
      if (progress != nullptr) progress->update(done);
    }
    if (progress != nullptr) progress->finish();

    uint8_t stored[TAG_LEN];
    bs9::read_exact(ifs, stored, TAG_LEN);
    const bs9::Digest computed = mac.final();
    if (!bs9::equal_constant_time(stored, computed.data(), computed.size())) {
      throw std::runtime_error("Wrong password or corrupted file");
    }

    output.commit();
    return bs9::path_to_utf8(out);
  }
}

#endif
