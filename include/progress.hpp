#ifndef _BS9_PSEUDO_PROGRESS
#define _BS9_PSEUDO_PROGRESS
// 进度条：只在交互式终端上启用，输出到 stderr，用 '\r' 原地刷新一行。
// 命令行层负责决定要不要创建它（--silent、重定向、非 TTY 时都不创建）。
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>

namespace bs9 {
  // 太小的文件画进度条只会闪一下，反而吵；低于这个大小直接不画。
  inline constexpr uint64_t PROGRESS_MIN_BYTES = 8ull * 1024ull * 1024ull;

  class Progress {
   public:
    explicit Progress(std::FILE* out = stderr) : out_(out) {}

    Progress(const Progress&) = delete;
    Progress& operator=(const Progress&) = delete;

    // 开始报告。total 是总字节数；label 是显示在行首的动作名（如 "encrypting"）。
    void begin(uint64_t total, std::string label) {
      total_ = total;
      label_ = std::move(label);
      started_ = clock_now();
      last_render_ = started_ - 10.0;
      last_length_ = 0;
      active_ = true;
      render(0, false);
    }

    void update(uint64_t done) {
      if (!active_) return;
      const double now = clock_now();
      // 限流：每 100 ms 最多重画一次，避免把终端刷屏拖慢主循环。
      if (now - last_render_ < 0.1 && done < total_) return;
      render(done, false);
    }

    void finish() {
      if (!active_) return;
      render(total_, true);
      active_ = false;
    }

    bool active() const { return active_; }

   private:
    static double clock_now() {
      return static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(
                                     std::chrono::steady_clock::now().time_since_epoch())
                                     .count()) /
             1e6;
    }

    static const char* format_bytes(double mib, char* out, size_t size) {
      if (mib >= 1024.0) {
        std::snprintf(out, size, "%.2f GiB", mib / 1024.0);
      } else if (mib >= 1.0) {
        std::snprintf(out, size, "%.1f MiB", mib);
      } else {
        std::snprintf(out, size, "%.0f KiB", mib * 1024.0);
      }
      return out;
    }

    static const char* format_eta(double seconds, char* out, size_t size) {
      if (seconds < 0 || seconds > 99.0 * 3600.0) {
        std::snprintf(out, size, "--:--");
      } else {
        const long total = static_cast<long>(seconds + 0.5);
        std::snprintf(out, size, "%02ld:%02ld", total / 60, total % 60);
      }
      return out;
    }

    void render(uint64_t done, bool final) {
      last_render_ = clock_now();
      const double elapsed = std::max(0.0, last_render_ - started_);
      const double done_mib = static_cast<double>(done) / (1024.0 * 1024.0);
      const double total_mib = static_cast<double>(total_) / (1024.0 * 1024.0);
      const double fraction = total_ == 0 ? 1.0 : std::min(1.0, static_cast<double>(done) / static_cast<double>(total_));
      const double rate = elapsed > 0.0001 ? done_mib / elapsed : 0.0;

      const int bar_width = 24;
      const int filled = static_cast<int>(fraction * bar_width + 0.5);
      std::string bar;
      bar.reserve(static_cast<size_t>(bar_width));
      for (int i = 0; i < bar_width; ++i) bar += (i < filled ? '#' : '.');

      char done_buf[32];
      char total_buf[32];
      char rate_buf[32];
      char eta_buf[16];
      format_bytes(done_mib, done_buf, sizeof(done_buf));
      format_bytes(total_mib, total_buf, sizeof(total_buf));
      std::snprintf(rate_buf, sizeof(rate_buf), "%.1f MiB/s", rate);
      const double remaining = (rate > 0.0001 && fraction < 1.0) ? (total_mib - done_mib) / rate : 0.0;
      format_eta(remaining, eta_buf, sizeof(eta_buf));

      char line[256];
      const int written = std::snprintf(line, sizeof(line), "%s [%s] %5.1f%%  %s / %s  %s  ETA %s", label_.c_str(),
                                        bar.c_str(), fraction * 100.0, done_buf, total_buf, rate_buf,
                                        fraction >= 1.0 ? "00:00" : eta_buf);
      if (written <= 0) return;

      std::string text = std::string("\r") + std::string(line, static_cast<size_t>(written));
      // 上一次的行更长时补空格擦掉尾巴。
      if (last_length_ > static_cast<size_t>(written)) text.append(last_length_ - static_cast<size_t>(written), ' ');
      last_length_ = static_cast<size_t>(written);
      if (final) text += '\n';
      std::fwrite(text.data(), 1, text.size(), out_);
      std::fflush(out_);
    }

    std::FILE* out_ = stderr;
    uint64_t total_ = 0;
    std::string label_;
    double started_ = 0.0;
    double last_render_ = 0.0;
    size_t last_length_ = 0;
    bool active_ = false;
  };
} // namespace bs9

#endif
