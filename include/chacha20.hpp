#include <cstdint>
#include <cstddef>
#include <cstring>

#ifndef _BS9_CHACHA20
#define _BS9_CHACHA20 1

namespace bs9 {
  inline uint32_t rotl32(uint32_t val, int bits) {
    return (val << bits) | (val >> (32 - bits));
  }

  inline uint32_t load32(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) | (static_cast<uint32_t>(data[3]) << 24);
  }

  inline void chacha_quarter(uint32_t x[16], int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = bs9::rotl32(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = bs9::rotl32(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = bs9::rotl32(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = bs9::rotl32(x[b] ^ x[c], 7);
  }

  inline void chacha20_block(uint32_t state[16], uint8_t out[64]) {
    uint32_t work[16];
    std::memcpy(work, state, sizeof(work));

    for (int i = 0; i < 10; ++i) {
      bs9::chacha_quarter(work, 0, 4, 8, 12);
      bs9::chacha_quarter(work, 1, 5, 9, 13);
      bs9::chacha_quarter(work, 2, 6, 10, 14);
      bs9::chacha_quarter(work, 3, 7, 11, 15);
      bs9::chacha_quarter(work, 0, 5, 10, 15);
      bs9::chacha_quarter(work, 1, 6, 11, 12);
      bs9::chacha_quarter(work, 2, 7, 8, 13);
      bs9::chacha_quarter(work, 3, 4, 9, 14);
    }

    for (int i = 0; i < 16; ++i) {
      const uint32_t val = work[i] + state[i];
      out[i * 4] = static_cast<uint8_t>(val);
      out[i * 4 + 1] = static_cast<uint8_t>(val >> 8);
      out[i * 4 + 2] = static_cast<uint8_t>(val >> 16);
      out[i * 4 + 3] = static_cast<uint8_t>(val >> 24);
    }

    ++state[12];
  }

  class ChaCha20 {
    uint32_t state_[16] = {};
    uint8_t block_[64] = {};
    size_t pos_ = 64;

  public:
    ChaCha20(const uint8_t* key, const uint8_t* nonce, uint32_t counter) {
      state_[0] = 0x61707865;
      state_[1] = 0x3320646e;
      state_[2] = 0x79622d32;
      state_[3] = 0x6b206574;
      for (int i = 0; i < 8; ++i) state_[4 + i] = bs9::load32(key + i * 4);
      state_[12] = counter;
      state_[13] = bs9::load32(nonce);
      state_[14] = bs9::load32(nonce + 4);
      state_[15] = bs9::load32(nonce + 8);
    }

    void fill(uint8_t* out, size_t len) {
      for (size_t i = 0; i < len; ++i) out[i] = next_byte();
    }

    void xor_data(uint8_t* data, size_t len) {
      for (size_t i = 0; i < len; ++i) data[i] ^= next_byte();
    }

  private:
    uint8_t next_byte() {
      if (pos_ == 64) {
        bs9::chacha20_block(state_, block_);
        pos_ = 0;
      }
      return block_[pos_++];
    }
  };
}

#endif
