#include <cstddef>
#include <string>

#include <openssl/crypto.h>

#ifndef _BS9_SECURE
#define _BS9_SECURE 1

namespace bs9 {
  // 尽量不被优化掉的擦除：编译器不能把 OPENSSL_cleanse 当死代码消除。
  inline void cleanse(void* data, size_t len) {
    if (data != nullptr && len > 0) {
      OPENSSL_cleanse(data, len);
    }
  }

  inline void cleanse_string(std::string& text) {
    if (!text.empty()) {
      OPENSSL_cleanse(text.data(), text.size());
    }
    text.clear();
    text.shrink_to_fit();
  }

  // 作用域退出时擦除一段内存，异常路径同样生效。
  class CleanseGuard {
    void* data_ = nullptr;
    size_t len_ = 0;

  public:
    CleanseGuard(void* data, size_t len) : data_(data), len_(len) {}
    CleanseGuard(const CleanseGuard&) = delete;
    CleanseGuard& operator=(const CleanseGuard&) = delete;
    ~CleanseGuard() { bs9::cleanse(data_, len_); }
  };
}

#endif
