#include <cstdint>
#include <cstddef>
#include <vector>
#include <istream>
#include <stdexcept>

#ifndef _BS9_CONV
#define _BS9_CONV 1

namespace bs9 {
  inline void append_uint16(std::vector<uint8_t>& buffer, uint16_t val) {
    buffer.push_back(static_cast<uint8_t>(val >> 8));
    buffer.push_back(static_cast<uint8_t>(val));
  }

  inline void append_uint32(std::vector<uint8_t>& buffer, uint32_t val) {
    buffer.push_back(static_cast<uint8_t>(val >> 24));
    buffer.push_back(static_cast<uint8_t>(val >> 16));
    buffer.push_back(static_cast<uint8_t>(val >> 8));
    buffer.push_back(static_cast<uint8_t>(val));
  }

  inline void append_uint64(std::vector<uint8_t>& buffer, uint64_t val) {
    for (int i = 7; i >= 0; --i) buffer.push_back(static_cast<uint8_t>(val >> (i * 8)));
  }

  inline void append_bytes(std::vector<uint8_t>& buffer, const uint8_t* data, size_t len) {
    if (len == 0) return;
    buffer.insert(buffer.end(), data, data + len);
  }

  inline uint16_t load_uint16(const uint8_t* data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]));
  }

  inline uint32_t load_uint32(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);
  }

  inline uint64_t load_uint64(const uint8_t* data) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) val = (val << 8) | static_cast<uint64_t>(data[i]);
    return val;
  }

  inline void read_exact(std::istream& is, uint8_t* out, size_t len) {
    if (len == 0) return;
    if (!is.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(len))) {
      throw std::runtime_error("Unexpected end of file");
    }
  }
}

#endif
