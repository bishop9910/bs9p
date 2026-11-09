#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "chacha20.hpp"
#include "secure.hpp"

#ifndef _BS9P_DATA_DICT
#define _BS9P_DATA_DICT 1

namespace bs9 {
  // 由 dict 子密钥派生出的 256 字节置换表（含反查表）。
  // 每个实例独占自己的表：不再有全局可变状态，多线程各自加密互不影响。
  // 洗牌算法与 v2 格式完全一致：dict 密钥 + 全零 nonce + counter 0 的 ChaCha20 密钥流，
  // 用拒绝采样驱动的 Fisher-Yates 洗牌。
  class DataDict {
    std::array<uint8_t, 256> forward_{};
    std::array<uint8_t, 256> reverse_{};

  public:
    explicit DataDict(const uint8_t* key) {
      const uint8_t nonce[bs9::CHACHA_NONCE_LEN] = {};
      bs9::ChaCha20 stream(key, nonce, 0);

      std::array<uint8_t, 256> values{};
      for (int i = 0; i < 256; ++i) values[i] = static_cast<uint8_t>(i);

      for (int i = 255; i > 0; --i) {
        const uint32_t limit = 256 - (256 % static_cast<uint32_t>(i + 1));
        uint8_t byte = 0;
        do {
          stream.fill(&byte, 1);
        } while (byte >= limit);
        std::swap(values[static_cast<size_t>(i)], values[byte % (i + 1)]);
      }

      for (int i = 0; i < 256; ++i) {
        forward_[i] = values[i];
        reverse_[values[i]] = static_cast<uint8_t>(i);
      }

      bs9::cleanse(values.data(), values.size());
    }

    DataDict(const DataDict&) = delete;
    DataDict& operator=(const DataDict&) = delete;

    ~DataDict() {
      bs9::cleanse(forward_.data(), forward_.size());
      bs9::cleanse(reverse_.data(), reverse_.size());
    }

    uint8_t encode(uint8_t byte) const { return forward_[byte]; }
    uint8_t decode(uint8_t byte) const { return reverse_[byte]; }
  };
}

#endif
