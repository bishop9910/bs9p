#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>

#include <openssl/evp.h>

#ifndef _BS9_CHACHA20
#define _BS9_CHACHA20 1

// RFC 8439 ChaCha20（IETF 变体：32 bit 计数器 + 96 bit nonce）。
// 加解密都由 OpenSSL 的 EVP_chacha20 完成：它和原先的手写实现同为 RFC 8439，
// 密钥流逐字节一致，因此已有密文格式不受影响。
//
// OpenSSL 的 EVP_chacha20 取 16 字节 IV：低 4 字节是小端计数器，高 12 字节是 nonce。
namespace bs9 {
  inline constexpr size_t CHACHA_KEY_LEN = 32;
  inline constexpr size_t CHACHA_NONCE_LEN = 12;
  inline constexpr size_t CHACHA_BLOCK_LEN = 64;

  // 从 counter 开始，这条密钥流最多还能产出多少字节而不回卷计数器。
  inline uint64_t chacha_max_bytes(uint32_t counter) {
    return (static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) - counter + 1ull) * CHACHA_BLOCK_LEN;
  }

  class ChaCha20 {
    EVP_CIPHER_CTX* ctx_ = nullptr;
    uint64_t used_ = 0;
    uint64_t capacity_ = 0;

  public:
    ChaCha20(const uint8_t* key, const uint8_t* nonce, uint32_t counter = 0) {
      std::array<uint8_t, 16> iv{};
      iv[0] = static_cast<uint8_t>(counter);
      iv[1] = static_cast<uint8_t>(counter >> 8);
      iv[2] = static_cast<uint8_t>(counter >> 16);
      iv[3] = static_cast<uint8_t>(counter >> 24);
      std::memcpy(iv.data() + 4, nonce, bs9::CHACHA_NONCE_LEN);

      ctx_ = EVP_CIPHER_CTX_new();
      if (ctx_ == nullptr) throw std::runtime_error("Failed to create ChaCha20 context");

      if (EVP_EncryptInit_ex(ctx_, EVP_chacha20(), nullptr, key, iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx_);
        ctx_ = nullptr;
        throw std::runtime_error("Failed to initialize ChaCha20");
      }

      capacity_ = bs9::chacha_max_bytes(counter);
    }

    ChaCha20(const ChaCha20&) = delete;
    ChaCha20& operator=(const ChaCha20&) = delete;

    ~ChaCha20() { EVP_CIPHER_CTX_free(ctx_); }

    // 原地 XOR；流密码加密与解密是同一个操作。
    void xor_data(uint8_t* data, size_t len) {
      if (len == 0) return;
      if (len > capacity_ - used_) {
        throw std::runtime_error("ChaCha20 counter overflow: file is too large for a single key stream");
      }

      size_t offset = 0;
      while (offset < len) {
        // EVP_EncryptUpdate 的长度参数是 int，分块避免溢出。
        const size_t step = std::min<size_t>(len - offset, size_t{1} << 30);
        int out_len = 0;
        if (EVP_EncryptUpdate(ctx_, data + offset, &out_len, data + offset, static_cast<int>(step)) != 1) {
          throw std::runtime_error("ChaCha20 encryption failed");
        }
        if (out_len != static_cast<int>(step)) {
          throw std::runtime_error("ChaCha20 produced an unexpected number of bytes");
        }
        offset += step;
      }

      used_ += len;
    }

    // 生成密钥流本身（用于置换表洗牌）。
    void fill(uint8_t* out, size_t len) {
      std::memset(out, 0, len);
      xor_data(out, len);
    }
  };
}

#endif
