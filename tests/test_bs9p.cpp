#ifdef _MSC_VER
// 测试里用 std::fopen 只是为了把进度条渲染结果落到文件，不是生产代码；
// 关掉 MSVC 的 C4996 才能保持零警告构建。
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "chacha20.hpp"
#include "core.hpp"
#include "data_dict.hpp"
#include "path_util.hpp"

namespace fs = std::filesystem;

namespace {
  int g_checks = 0;
  int g_failures = 0;

  void fail(const char* file, int line, const char* what) {
    std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, what);
    ++g_failures;
  }

  // 出问题（尤其平台相关的路径/编码异常）时，设 BS9P_TEST_TRACE=1 就能看到卡在哪一步。
  bool trace_enabled() {
#ifdef _MSC_VER
    char* buffer = nullptr;
    size_t size = 0;
    const bool present = ::_dupenv_s(&buffer, &size, "BS9P_TEST_TRACE") == 0 && buffer != nullptr;
    std::free(buffer);
    return present;
#else
    return std::getenv("BS9P_TEST_TRACE") != nullptr;
#endif
  }

  void trace(const char* step) {
    if (trace_enabled()) std::fprintf(stderr, "[trace] %s\n", step);
  }
}

#define CHECK(expr) do { ++g_checks; if (!(expr)) fail(__FILE__, __LINE__, #expr); } while (0)
#define CHECK_THROWS(expr) do {                                                       \
  ++g_checks;                                                                         \
  bool threw_ = false;                                                                \
  try { expr; } catch (const std::exception&) { threw_ = true; }                      \
  if (!threw_) fail(__FILE__, __LINE__, "expected exception: " #expr);                \
} while (0)

namespace {
  // ---------------------------------------------------------------------------
  // 独立的 RFC 8439 参考实现：用来交叉验证 OpenSSL EVP_chacha20 的 IV 布局与
  // 密钥流是否与原先的手写实现逐字节一致（也就是旧密文能否继续解开）。
  // ---------------------------------------------------------------------------
  uint32_t rotl32(uint32_t value, int bits) {
    return (value << bits) | (value >> (32 - bits));
  }

  uint32_t load32le(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) | (static_cast<uint32_t>(data[3]) << 24);
  }

  void quarter_round(uint32_t x[16], int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);
  }

  void reference_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]) {
    uint32_t state[16] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
    for (int i = 0; i < 8; ++i) state[4 + i] = load32le(key + i * 4);
    state[12] = counter;
    for (int i = 0; i < 3; ++i) state[13 + i] = load32le(nonce + i * 4);

    uint32_t work[16];
    std::memcpy(work, state, sizeof(work));
    for (int i = 0; i < 10; ++i) {
      quarter_round(work, 0, 4, 8, 12);
      quarter_round(work, 1, 5, 9, 13);
      quarter_round(work, 2, 6, 10, 14);
      quarter_round(work, 3, 7, 11, 15);
      quarter_round(work, 0, 5, 10, 15);
      quarter_round(work, 1, 6, 11, 12);
      quarter_round(work, 2, 7, 8, 13);
      quarter_round(work, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; ++i) {
      const uint32_t value = work[i] + state[i];
      out[i * 4 + 0] = static_cast<uint8_t>(value);
      out[i * 4 + 1] = static_cast<uint8_t>(value >> 8);
      out[i * 4 + 2] = static_cast<uint8_t>(value >> 16);
      out[i * 4 + 3] = static_cast<uint8_t>(value >> 24);
    }
  }

  void test_chacha20() {
    // ChaCha20 公开测试向量 #1（key = 00..1f，nonce = 00 00 00 09 00 00 00 4a 00 00 00 00，counter = 1）
    uint8_t key[32];
    for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);
    const uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

    const uint8_t expected[64] = {
      0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
      0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
      0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
      0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    };

    uint8_t actual[64] = {};
    bs9::ChaCha20 stream(key, nonce, 1);
    stream.fill(actual, sizeof(actual));
    CHECK(std::memcmp(actual, expected, sizeof(expected)) == 0);

    // RFC 8439 §2.3.2 的块函数向量（全零 key / nonce，counter = 0）
    {
      const uint8_t zero_key[32] = {};
      const uint8_t zero_nonce[12] = {};
      const uint8_t zero_expected[32] = {
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
        0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
        0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
        0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
      };
      uint8_t zero_actual[32] = {};
      bs9::ChaCha20 zero_stream(zero_key, zero_nonce, 0);
      zero_stream.fill(zero_actual, sizeof(zero_actual));
      CHECK(std::memcmp(zero_actual, zero_expected, sizeof(zero_expected)) == 0);
    }

    // EVP 实现与参考实现逐块对比：任意 key / nonce / counter 都必须完全一致。
    std::mt19937 rng(0x5eed9b9);
    for (int round = 0; round < 32; ++round) {
      uint8_t random_key[32];
      uint8_t random_nonce[12];
      for (auto& byte : random_key) byte = static_cast<uint8_t>(rng() & 0xff);
      for (auto& byte : random_nonce) byte = static_cast<uint8_t>(rng() & 0xff);
      const uint32_t counter = rng();

      std::array<uint8_t, 256> evp_stream{};
      bs9::ChaCha20 evp(random_key, random_nonce, counter);
      evp.fill(evp_stream.data(), evp_stream.size());

      std::array<uint8_t, 256> reference{};
      for (int block = 0; block < 4; ++block) {
        reference_block(random_key, random_nonce, counter + static_cast<uint32_t>(block),
                        reference.data() + block * 64);
      }
      CHECK(std::memcmp(evp_stream.data(), reference.data(), reference.size()) == 0);
    }

    // 任意长度分块调用必须与一次性调用等价（EVP 内部要跨调用保留不足一块的密钥流）。
    std::array<uint8_t, 300> bulk{};
    std::array<uint8_t, 300> piecewise{};
    bs9::ChaCha20 bulk_stream(key, nonce, 7);
    bulk_stream.fill(bulk.data(), bulk.size());
    bs9::ChaCha20 piece_stream(key, nonce, 7);
    piece_stream.fill(piecewise.data(), 37);
    piece_stream.fill(piecewise.data() + 37, 1);
    piece_stream.fill(piecewise.data() + 38, 64);
    piece_stream.fill(piecewise.data() + 102, 198);
    CHECK(std::memcmp(bulk.data(), piecewise.data(), bulk.size()) == 0);

    // 计数器上限：counter 取最大值时只允许再产出一块。
    CHECK(bs9::chacha_max_bytes(0) == 256ull * 1024ull * 1024ull * 1024ull);
    CHECK(bs9::chacha_max_bytes(0xFFFFFFFFu) == 64);
  }

  void test_data_dict() {
    std::array<uint8_t, 32> key{};
    for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i * 7 + 3);

    const bs9::DataDict first(key.data());
    const bs9::DataDict second(key.data());

    std::array<bool, 256> seen{};
    for (int i = 0; i < 256; ++i) {
      const uint8_t encoded = first.encode(static_cast<uint8_t>(i));
      CHECK(first.decode(encoded) == static_cast<uint8_t>(i));      // 可逆
      CHECK(second.encode(static_cast<uint8_t>(i)) == encoded);      // 同密钥确定性
      CHECK(!seen[encoded]);
      seen[encoded] = true;
    }

    key[0] ^= 0x5a;
    const bs9::DataDict other(key.data());
    bool differs = false;
    for (int i = 0; i < 256; ++i) {
      if (other.encode(static_cast<uint8_t>(i)) != first.encode(static_cast<uint8_t>(i))) differs = true;
    }
    CHECK(differs);
  }

  void test_header() {
    const bs9::Header original = bs9::make_header(".pdf", 123456789ull);
    CHECK(original.size == 50 + 4);
    CHECK(original.iterations == bs9::PBKDF2_ITERATIONS);

    std::stringstream buffer(std::ios::in | std::ios::out | std::ios::binary);
    buffer.write(reinterpret_cast<const char*>(original.raw.data()),
                 static_cast<std::streamsize>(original.raw.size()));
    buffer.seekg(0);

    const bs9::Header parsed = bs9::read_header(buffer);
    CHECK(parsed.size == original.size);
    CHECK(parsed.plain_len == original.plain_len);
    CHECK(parsed.iterations == original.iterations);
    CHECK(parsed.extension == ".pdf");
    CHECK(parsed.raw == original.raw);

    // 没有扩展名的文件
    const bs9::Header bare = bs9::make_header("", 0);
    CHECK(bare.extension.empty());
    CHECK(bare.size == 50);

    // magic 被改：必须拒绝
    std::stringstream corrupted(std::ios::in | std::ios::out | std::ios::binary);
    std::vector<uint8_t> bytes = original.raw;
    bytes[0] ^= 0xff;
    corrupted.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    corrupted.seekg(0);
    CHECK_THROWS(bs9::read_header(corrupted));

    // 旧版本的 magic（1.0.3 的 BS9P103、以及更早的 BS91002）不再兼容
    for (const char* old_magic : {"BS9P103", "BS91002"}) {
      std::stringstream legacy(std::ios::in | std::ios::out | std::ios::binary);
      std::vector<uint8_t> legacy_bytes = original.raw;
      std::memcpy(legacy_bytes.data(), old_magic, 7);
      legacy_bytes[7] = 0;
      legacy.write(reinterpret_cast<const char*>(legacy_bytes.data()),
                   static_cast<std::streamsize>(legacy_bytes.size()));
      legacy.seekg(0);
      CHECK_THROWS(bs9::read_header(legacy));
    }

    // 头被截断：必须拒绝
    std::stringstream truncated(std::ios::in | std::ios::out | std::ios::binary);
    truncated.write(reinterpret_cast<const char*>(original.raw.data()), 10);
    truncated.seekg(0);
    CHECK_THROWS(bs9::read_header(truncated));

    // 扩展名净化
    CHECK_THROWS(bs9::validate_extension("../evil"));
    CHECK_THROWS(bs9::validate_extension("evil"));
    CHECK_THROWS(bs9::validate_extension(".a/b"));
    CHECK_THROWS(bs9::validate_extension(".a\\b"));
    CHECK_THROWS(bs9::validate_extension(".a:b"));
    CHECK_THROWS(bs9::validate_extension(std::string(".a") + std::string(1, '\x01')));
    CHECK_THROWS(bs9::validate_extension("." + std::string(300, 'a')));
    bs9::validate_extension("");
    bs9::validate_extension(".pdf");
    bs9::validate_extension(".tar.gz");
    bs9::validate_extension(".中文");
  }

  // ---------------------------------------------------------------------------
  // 文件级往返
  // ---------------------------------------------------------------------------
  fs::path make_temp_dir() {
    std::mt19937_64 rng(static_cast<uint64_t>(std::random_device{}()));
    for (int attempt = 0; attempt < 16; ++attempt) {
      const fs::path dir = fs::temp_directory_path() / ("bs9p-test-" + std::to_string(rng()));
      std::error_code ec;
      if (fs::create_directories(dir, ec) && !ec) return dir;
    }
    throw std::runtime_error("Failed to create a temporary directory");
  }

  std::vector<uint8_t> make_payload(size_t size, uint32_t seed) {
    std::vector<uint8_t> data(size);
    std::mt19937 rng(seed);
    for (auto& byte : data) byte = static_cast<uint8_t>(rng() & 0xff);
    return data;
  }

  void write_file(const fs::path& path, const std::vector<uint8_t>& data) {
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    out.close();
    if (!out) throw std::runtime_error("write_file failed");
  }

  std::vector<uint8_t> read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return data;
  }

  size_t count_temp_files(const fs::path& dir) {
    size_t count = 0;
    for (const auto& entry : fs::directory_iterator(dir)) {
      if (bs9::path_to_utf8(entry.path().filename()).find(".tmp-") != std::string::npos) ++count;
    }
    return count;
  }

  void test_roundtrip() {
    const fs::path dir = make_temp_dir();
    const std::string password = "correct horse battery staple 密码";

    const std::array<size_t, 10> sizes = {0, 1, 63, 64, 65, 1000, 65535, 65536, 65537, 300000};
    for (size_t index = 0; index < sizes.size(); ++index) {
      const fs::path plain = dir / ("doc" + std::to_string(index) + ".pdf");
      const std::vector<uint8_t> original = make_payload(sizes[index], static_cast<uint32_t>(index * 7919 + 1));
      write_file(plain, original);

      const std::string encoded = bs9::encode_file(plain, password);
      CHECK(fs::exists(encoded));
      CHECK(fs::path(encoded).filename() == plain.filename().string() + ".bs9p");
      CHECK(fs::file_size(encoded) == original.size() + std::string(".pdf").size() + 82);

      fs::remove(plain);

      // 内存路径（默认阈值）
      const std::string decoded = bs9::decode_file(bs9::path_from_utf8(encoded), password);
      CHECK(fs::path(decoded) == plain);
      CHECK(read_file(decoded) == original);
      fs::remove(decoded);

      // 大文件路径（阈值 0 强制走流式）
      if (!original.empty()) {
        const std::string streamed = bs9::decode_file(bs9::path_from_utf8(encoded), password, 0);
        CHECK(fs::path(streamed) == plain);
        CHECK(read_file(streamed) == original);
        fs::remove(streamed);
      }

      fs::remove(encoded);
      CHECK(count_temp_files(dir) == 0);
    }

    fs::remove_all(dir);
  }

  // 非 ASCII 路径：中文、日文假名、片假名中点 U+30FB、空格。
  // U+30FB 在 Windows 的 CP936 / CP932 里没有映射，一旦走了 ACP 转换就会变成 '?'，
  // 所以这里同时验证「字符串 -> 路径」与「文件头里的扩展名」都按 UTF-8 走通。
  void test_unicode_paths() {
    const fs::path dir = make_temp_dir();
    const std::string password = "pw-unicode";

    {
      trace("unicode: build path");
      const fs::path plain = dir / fs::u8path("(18禁ゲームCG) [ゆずソフト] ライムライト・レモネード ジャム.7z");
      const std::vector<uint8_t> original = make_payload(20000, 7);
      trace("unicode: write plain");
      write_file(plain, original);

      trace("unicode: encode");
      const std::string encoded = bs9::encode_file(plain, password);
      CHECK(encoded == bs9::path_to_utf8(plain) + ".bs9p");
      CHECK(fs::exists(fs::u8path(encoded)));

      fs::remove(plain);
      trace("unicode: decode");
      const std::string decoded = bs9::decode_file(bs9::path_from_utf8(encoded), password);
      CHECK(decoded == bs9::path_to_utf8(plain));
      CHECK(read_file(plain) == original);
      CHECK(count_temp_files(dir) == 0);

      fs::remove(plain);
      fs::remove(fs::u8path(encoded));
    }

    {
      // 扩展名本身也含非 ASCII：文件头里存的是 UTF-8 字节，解密时要能原样拼回名字。
      const fs::path plain = dir / fs::u8path("中文・文件名.文档");
      const std::vector<uint8_t> original = make_payload(4096, 9);
      write_file(plain, original);

      const std::string encoded = bs9::encode_file(plain, password);
      CHECK(encoded == bs9::path_to_utf8(plain) + ".bs9p");

      fs::remove(plain);
      CHECK(bs9::decode_file(bs9::path_from_utf8(encoded), password) == bs9::path_to_utf8(plain));
      CHECK(read_file(plain) == original);
      CHECK(count_temp_files(dir) == 0);

      fs::remove(plain);
      fs::remove(fs::u8path(encoded));
    }

    fs::remove_all(dir);
  }

  // IO 选项：--out（文件或目录）、--buffer-size 两端、进度条渲染。
  void test_io_options() {
    const fs::path dir = make_temp_dir();
    const std::string password = "pw-io-options";

    // 1) clamp 的边界行为
    CHECK(bs9::clamp_buffer_size(0) == bs9::MIN_BUFFER_SIZE);
    CHECK(bs9::clamp_buffer_size(1) == bs9::MIN_BUFFER_SIZE);
    CHECK(bs9::clamp_buffer_size(bs9::MAX_BUFFER_SIZE + 1) == bs9::MAX_BUFFER_SIZE);
    CHECK(bs9::clamp_buffer_size(123456) == 123456);

    const fs::path plain = dir / "option.bin";
    const std::vector<uint8_t> original = make_payload(200000, 77);
    write_file(plain, original);

    // 2) --out 给目录：密文放进该目录并沿用默认文件名，解密也落在同一目录
    {
      const fs::path outdir = dir / "out";
      fs::create_directories(outdir);
      bs9::IoOptions io;
      io.output = outdir;
      const std::string encoded = bs9::encode_file(plain, password, io);
      CHECK(fs::path(bs9::path_from_utf8(encoded)) == outdir / "option.bin.bs9p");

      const std::string decoded = bs9::decode_file(bs9::path_from_utf8(encoded), password);
      CHECK(fs::path(bs9::path_from_utf8(decoded)) == outdir / "option.bin");
      CHECK(read_file(fs::path(bs9::path_from_utf8(decoded))) == original);

      fs::remove(fs::path(bs9::path_from_utf8(encoded)));
      fs::remove(fs::path(bs9::path_from_utf8(decoded)));
      fs::remove(outdir);
    }

    // 3) 缓冲大小两端：64 KiB 与 64 MiB 都要正确往返（第三条参数 0 强制走流式解密路径）
    for (const size_t buffer_size : {bs9::MIN_BUFFER_SIZE, bs9::MAX_BUFFER_SIZE}) {
      bs9::IoOptions io;
      io.buffer_size = buffer_size;
      const std::string encoded = bs9::encode_file(plain, password, io);
      CHECK(fs::file_size(fs::path(bs9::path_from_utf8(encoded))) == original.size() + 4 + 82);
      fs::remove(plain);

      const std::string decoded = bs9::decode_file(bs9::path_from_utf8(encoded), password, 0, io);
      CHECK(fs::path(bs9::path_from_utf8(decoded)) == plain);
      CHECK(read_file(plain) == original);

      fs::remove(fs::path(bs9::path_from_utf8(encoded)));
      CHECK(count_temp_files(dir) == 0);
    }

    // 4) 进度条渲染：写进普通文件后检查内容（不依赖 stderr 是否为终端）
    {
      const fs::path log = dir / "progress.log";
      std::FILE* fp = std::fopen(bs9::path_to_utf8(log).c_str(), "wb");
      CHECK(fp != nullptr);
      if (fp) {
        {
          bs9::Progress progress(fp);
          progress.begin(16ull * 1024 * 1024, "encrypting");
          progress.update(8ull * 1024 * 1024);
          progress.finish();
        }
        std::fclose(fp);
        const std::vector<uint8_t> raw = read_file(log);
        const std::string text(raw.begin(), raw.end());
        CHECK(text.find("encrypting") != std::string::npos);
        CHECK(text.find("100.0%") != std::string::npos);
        CHECK(text.find("ETA") != std::string::npos);
        fs::remove(log);
      }
    }

    fs::remove_all(dir);
  }

  void test_failures() {
    const fs::path dir = make_temp_dir();
    const std::string password = "pw-for-failure-tests";
    const fs::path plain = dir / "secret.bin";
    const std::vector<uint8_t> original = make_payload(100000, 42);
    write_file(plain, original);

    const std::string encoded = bs9::encode_file(plain, password);
    fs::remove(plain);

    // 1) 密码错误：抛异常，且不留下输出文件与临时文件
    CHECK_THROWS(bs9::decode_file(bs9::path_from_utf8(encoded), "wrong password"));
    CHECK(!fs::exists(plain));
    CHECK(count_temp_files(dir) == 0);

    // 2) 篡改密文中间的一个字节
    {
      std::vector<uint8_t> tampered = read_file(encoded);
      tampered[tampered.size() / 2] ^= 0x01;
      const fs::path bad = dir / "tampered.bin.bs9p";
      write_file(bad, tampered);
      CHECK_THROWS(bs9::decode_file(bad, password));
      CHECK(!fs::exists(dir / "tampered.bin"));
      CHECK(count_temp_files(dir) == 0);
      fs::remove(bad);
    }

    // 3) 截断（少一个字节）
    {
      std::vector<uint8_t> truncated = read_file(encoded);
      truncated.pop_back();
      const fs::path bad = dir / "truncated.bin.bs9p";
      write_file(bad, truncated);
      CHECK_THROWS(bs9::decode_file(bad, password));
      CHECK(!fs::exists(dir / "truncated.bin"));
      fs::remove(bad);
    }

    // 4) 目标文件已存在：拒绝覆盖，原有内容保持不变
    {
      const std::vector<uint8_t> sentinel = {1, 2, 3, 4, 5};
      write_file(plain, sentinel);
      CHECK_THROWS(bs9::decode_file(bs9::path_from_utf8(encoded), password));
      CHECK(read_file(plain) == sentinel);
      fs::remove(plain);
    }

    // 5) 加密时目标文件已存在
    {
      write_file(plain, original);
      write_file(fs::path(bs9::path_from_utf8(encoded)), {9, 9, 9});
      CHECK_THROWS(bs9::encode_file(plain, password));
      CHECK(read_file(encoded) == std::vector<uint8_t>({9, 9, 9}));
      fs::remove(encoded);
      fs::remove(plain);
    }

    // 6) 解密目标路径正好等于输入路径（密文被改名成没有 .bs9p 后缀的原始文件名）
    {
      const fs::path weird = dir / "payload.pdf";
      write_file(weird, original);
      const std::string weird_encoded = bs9::encode_file(weird, password);  // payload.pdf.bs9p
      fs::remove(weird);
      fs::rename(weird_encoded, weird);

      const std::vector<uint8_t> before = read_file(weird);
      CHECK_THROWS(bs9::decode_file(weird, password));
      CHECK(read_file(weird) == before);   // 密文必须原封不动
      fs::remove(weird);
    }

    fs::remove_all(dir);
  }
}

int main() {
  try {
    test_chacha20();
    test_data_dict();
    test_header();
    test_roundtrip();
    test_unicode_paths();
    test_io_options();
    test_failures();
  } catch (const std::exception& e) {
    std::fprintf(stderr, "UNEXPECTED EXCEPTION: %s\n", e.what());
    return 2;
  }

  std::printf("%d checks, %d failure(s)\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
