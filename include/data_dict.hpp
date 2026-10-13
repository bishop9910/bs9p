#include <cstdint>
#include <array>
#include <algorithm>

#include "chacha20.hpp"

#ifndef _BS9P_DATA_DICT
#define _BS9P_DATA_DICT 1

namespace bs9 {
  inline std::array<uint8_t, 256> data_dict;
  inline std::array<uint8_t, 256> reverse_dict;

  inline void init_data_dict(const uint8_t* key) {
    const uint8_t nonce[12] = {};
    bs9::ChaCha20 stream(key, nonce, 0);

    std::array<uint8_t, 256> values;
    for (int i = 0; i < 256; ++i) values[i] = static_cast<uint8_t>(i);

    for (int i = 255; i > 0; --i) {
      const uint32_t limit = 256 - (256 % (i + 1));
      uint8_t byte;
      do {
        stream.fill(&byte, 1);
      } while (byte >= limit);
      std::swap(values[i], values[byte % (i + 1)]);
    }

    for (int i = 0; i < 256; ++i) {
      data_dict[i] = values[i];
      reverse_dict[values[i]] = static_cast<uint8_t>(i);
    }
  }
}

#endif
