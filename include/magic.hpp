#include <cstdint>

#ifndef _BS9_MAGIC
#define _BS9_MAGIC 1

namespace bs9 {
  inline const char magic_buf[8] = {'B', 'S', '9', '1', '0', '0', '2', '\0'};

  inline uint64_t build_magic(const char* str) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
      val = (val << 8) | static_cast<uint8_t>(str[i]);
    }
    return val;
  }
}

#endif
