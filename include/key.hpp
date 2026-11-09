#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "secure.hpp"
#include "sha256.hpp"

#ifndef _BS9_KEY
#define _BS9_KEY 1

namespace bs9 {
  // 三把 32 字节子密钥。析构时自动擦除，禁止拷贝（拷贝会让擦除漏掉副本），
  // 允许移动以便 derive_keys 按值返回，移动源析构时擦除它自己那份副本。
  struct KeySet {
    Digest stream{};
    Digest mac{};
    Digest dict{};

    KeySet() = default;
    KeySet(const KeySet&) = delete;
    KeySet& operator=(const KeySet&) = delete;
    KeySet(KeySet&& other) noexcept : stream(other.stream), mac(other.mac), dict(other.dict) {}
    KeySet& operator=(KeySet&&) = delete;

    ~KeySet() {
      bs9::cleanse(stream.data(), stream.size());
      bs9::cleanse(mac.data(), mac.size());
      bs9::cleanse(dict.data(), dict.size());
    }
  };

  inline void random_bytes(uint8_t* out, size_t len) {
    if (len == 0) return;
    if (RAND_bytes(out, static_cast<int>(len)) != 1) throw std::runtime_error("Failed to generate random bytes");
  }

  inline Digest pbkdf2_hmac_sha256(const std::string& password, const uint8_t* salt, size_t salt_len,
                                   uint32_t iterations) {
    if (iterations == 0) throw std::invalid_argument("Iteration count must be positive");

    Digest result = {};
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), salt, static_cast<int>(salt_len),
                          static_cast<int>(iterations), EVP_sha256(), static_cast<int>(result.size()),
                          result.data()) != 1) {
      throw std::runtime_error("Failed to derive key");
    }
    return result;
  }

  inline Digest expand_key(const Digest& master, const std::string& label) {
    bs9::HmacSha256 hmac(master.data(), master.size());
    hmac.update(reinterpret_cast<const uint8_t*>(label.data()), label.size());
    return hmac.final();
  }

  inline KeySet derive_keys(const std::string& password, const uint8_t* salt, size_t salt_len,
                            uint32_t iterations) {
    Digest master = bs9::pbkdf2_hmac_sha256(password, salt, salt_len, iterations);
    // master 本身也是密钥材料：无论正常返回还是中途抛异常，离开作用域即擦除。
    const bs9::CleanseGuard master_guard(master.data(), master.size());

    bs9::KeySet keys;
    keys.stream = bs9::expand_key(master, "bs9p/stream");
    keys.mac = bs9::expand_key(master, "bs9p/mac");
    keys.dict = bs9::expand_key(master, "bs9p/dict");
    return keys;
  }

  inline bool equal_constant_time(const uint8_t* left, const uint8_t* right, size_t len) {
    return CRYPTO_memcmp(left, right, len) == 0;
  }
}

#endif
