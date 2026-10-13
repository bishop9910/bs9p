#include <cstdint>
#include <cstddef>
#include <string>
#include <stdexcept>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "sha256.hpp"

#ifndef _BS9_KEY
#define _BS9_KEY 1

namespace bs9 {
  struct KeySet {
    Digest stream;
    Digest mac;
    Digest dict;
  };

  inline void random_bytes(uint8_t* out, size_t len) {
    if (len == 0) return;
    if (RAND_bytes(out, static_cast<int>(len)) != 1) throw std::runtime_error("Failed to generate random bytes");
  }

  inline Digest pbkdf2_hmac_sha256(const std::string& password, const uint8_t* salt, size_t salt_len, uint32_t iterations) {
    if (iterations == 0) throw std::invalid_argument("Iteration count must be positive");

    Digest result = {};
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), salt, static_cast<int>(salt_len),
                          static_cast<int>(iterations), EVP_sha256(), static_cast<int>(result.size()), result.data()) != 1) {
      throw std::runtime_error("Failed to derive key");
    }
    return result;
  }

  inline Digest expand_key(const Digest& master, const std::string& label) {
    bs9::HmacSha256 hmac(master.data(), master.size());
    hmac.update(reinterpret_cast<const uint8_t*>(label.data()), label.size());
    return hmac.final();
  }

  inline KeySet derive_keys(const std::string& password, const uint8_t* salt, size_t salt_len, uint32_t iterations) {
    const Digest master = bs9::pbkdf2_hmac_sha256(password, salt, salt_len, iterations);

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
