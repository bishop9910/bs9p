#include <cstdint>
#include <cstddef>
#include <array>
#include <stdexcept>

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>

#ifndef _BS9_SHA256
#define _BS9_SHA256 1

namespace bs9 {
  using Digest = std::array<uint8_t, 32>;

  class Sha256 {
    EVP_MD_CTX* ctx_ = nullptr;

  public:
    Sha256() {
      ctx_ = EVP_MD_CTX_new();
      if (ctx_ == nullptr) throw std::runtime_error("Failed to create SHA-256 context");
      if (EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx_);
        throw std::runtime_error("Failed to initialize SHA-256");
      }
    }

    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;

    ~Sha256() { EVP_MD_CTX_free(ctx_); }

    void update(const uint8_t* data, size_t len) {
      if (len == 0) return;
      if (EVP_DigestUpdate(ctx_, data, len) != 1) throw std::runtime_error("Failed to update SHA-256");
    }

    [[nodiscard]] Digest final() const {
      EVP_MD_CTX* copy = EVP_MD_CTX_new();
      if (copy == nullptr) throw std::runtime_error("Failed to create SHA-256 context");

      Digest digest = {};
      unsigned int len = 0;
      if (EVP_MD_CTX_copy_ex(copy, ctx_) != 1 || EVP_DigestFinal_ex(copy, digest.data(), &len) != 1) {
        EVP_MD_CTX_free(copy);
        throw std::runtime_error("Failed to finalize SHA-256");
      }

      EVP_MD_CTX_free(copy);
      return digest;
    }
  };

  inline Digest sha256(const uint8_t* data, size_t len) {
    bs9::Sha256 hash;
    hash.update(data, len);
    return hash.final();
  }

  class HmacSha256 {
    EVP_MAC* mac_ = nullptr;
    EVP_MAC_CTX* ctx_ = nullptr;

    void release() {
      EVP_MAC_CTX_free(ctx_);
      EVP_MAC_free(mac_);
      ctx_ = nullptr;
      mac_ = nullptr;
    }

  public:
    HmacSha256(const uint8_t* key, size_t len) {
      mac_ = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
      if (mac_ == nullptr) throw std::runtime_error("Failed to fetch HMAC");

      ctx_ = EVP_MAC_CTX_new(mac_);
      if (ctx_ == nullptr) {
        release();
        throw std::runtime_error("Failed to create HMAC context");
      }

      char digest_name[] = "SHA256";
      OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0),
        OSSL_PARAM_construct_end()
      };
      if (EVP_MAC_init(ctx_, key, len, params) != 1) {
        release();
        throw std::runtime_error("Failed to initialize HMAC");
      }
    }

    HmacSha256(const HmacSha256&) = delete;
    HmacSha256& operator=(const HmacSha256&) = delete;

    ~HmacSha256() { release(); }

    void update(const uint8_t* data, size_t len) {
      if (len == 0) return;
      if (EVP_MAC_update(ctx_, data, len) != 1) throw std::runtime_error("Failed to update HMAC");
    }

    [[nodiscard]] Digest final() const {
      EVP_MAC_CTX* copy = EVP_MAC_CTX_dup(ctx_);
      if (copy == nullptr) throw std::runtime_error("Failed to copy HMAC context");

      Digest digest = {};
      size_t len = 0;
      if (EVP_MAC_final(copy, digest.data(), &len, digest.size()) != 1) {
        EVP_MAC_CTX_free(copy);
        throw std::runtime_error("Failed to finalize HMAC");
      }

      EVP_MAC_CTX_free(copy);
      return digest;
    }
  };
}

#endif
