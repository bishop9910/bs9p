# bs9p

一个用 C++17 写的命令行文件加密/解密工具：把任意文件编码成 `.bs9p` 密文，支持任意字符串密码，ChaCha20 流加密 + 密钥驱动的逐字节置换 + HMAC-SHA256 认证。

## 特性

- **密码加密** —— 密码是任意字符串（不再是数字种子），PBKDF2-HMAC-SHA256 迭代 200000 轮派生密钥
- **流式处理** —— 64 KiB 分块读写，内存占用恒定，多大的文件都能处理
- **认证加密（encrypt-then-MAC）** —— HMAC-SHA256 覆盖「文件头 + 密文」，解密时**先验 MAC 再落盘**，密码错/被篡改不会写出任何明文
- **两层保护** —— 先按 `dict` 密钥派生的 256 字节置换表逐字节映射，再 ChaCha20 XOR
- **保留扩展名** —— 原始扩展名明文存在文件头里，解密自动还原 `report.pdf.bs9p` → `report.pdf`
- **拒绝覆盖** —— 目标文件已存在直接报错，绝不覆盖已有文件
- **常量时间比较** —— MAC 用 `CRYPTO_memcmp` 比较，避免计时侧信道

## 依赖

- **CMake** >= 3.31
- **C++17** 编译器（MSVC 19.51 / GCC）
- **vcpkg** 管理第三方库

vcpkg 依赖：

- [`CLI11`](https://github.com/CLIUtils/CLI11) —— 命令行解析
- [`OpenSSL`](https://www.openssl.org/)（libcrypto）—— SHA-256 / HMAC-SHA256 / PBKDF2 / 随机数

> ChaCha20 与置换表是手写实现（`include/chacha20.hpp`、`include/data_dict.hpp`），不走 OpenSSL 的 EVP 接口，以保证与历史版本的密文格式一致。

## 构建

### 1. 设置 vcpkg

```bash
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh       # Linux / macOS
.\bootstrap-vcpkg.bat      # Windows
```

设置环境变量：

```bash
export VCPKG_ROOT=/path/to/vcpkg    # Linux / macOS
setx VCPKG_ROOT D:\path\to\vcpkg    # Windows
```

### 2. 构建

```bash
cmake --preset=default
cmake --build --preset=default
```

产物：`build/default/src/Release/bs9p.exe`（Release 配置；`libcrypto-3-x64.dll` 会自动拷到 exe 同目录）

**说明**：

- `default` 预设继承 `CMakePresets.json` 里的 `msvc`；`CMakeUserPresets.json` 还会把 `VCPKG_ROOT` 直接写进预设环境（该文件已被 `.gitignore` 忽略）。
- `CMakePresets.json` 里另有 `msvc` / `gcc` / `clang` 预设，用它们时需要自己在环境里提供 `VCPKG_ROOT`。
- Windows 下本工程用静态 CRT（`CMAKE_MSVC_RUNTIME_LIBRARY = MultiThreaded`），OpenSSL 用 vcpkg `x64-windows` 的动态库，只有 `libcrypto-3-x64.dll` 需要在 exe 旁边。
- vcpkg 走 manifest 模式，依赖装在 `build/<preset>/vcpkg_installed/` 里，不污染 `VCPKG_ROOT/installed`。
- `vcpkg-configuration.json` 的 registry 是 git 源且锁了 baseline，每次 configure 都会去 GitHub 取一次 registry 信息；本机连不上 GitHub 时先开代理，或改用本地 vcpkg 检出。

## 使用

### 基本用法

```bash
bs9p <encode|decode> <password> <input>
```

| mode | 作用 |
|---|---|
| `encode` | 加密：`report.pdf` → `report.pdf.bs9p` |
| `decode` | 解密：`report.pdf.bs9p` → `report.pdf` |

### 示例

```bash
# 加密（密码含空格要加引号）
bs9p encode "my secret password" report.pdf
# → report.pdf.bs9p

# 解密（按文件头里存的扩展名还原）
bs9p decode "my secret password" report.pdf.bs9p
# → report.pdf

# 版本 / 帮助
bs9p --version
bs9p --help
```

`--version` 输出：`Bs9p tool version: 2.0.0.0 last_update: 2026/9/23`

## 命令行参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `mode` | 位置参数，只接受 `encode` / `decode` | 必填 |
| `password` | 位置参数，密码，任意字符串 | 必填 |
| `input` | 位置参数，输入文件路径 | 必填 |
| `-h, --help` | 显示帮助并退出 | — |
| `-v, --version` | 显示版本并退出 | — |

三个位置参数按顺序匹配；参数不合法或缺参数时 CLI11 打印错误与退出码，运行时错误打到 stderr，成功返回 `0`、失败返回非 `0`。

## 文件格式

所有整数**大端**存储。文件头（`header.raw`）就是 HMAC 覆盖的前半段：

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 8 | magic | `42 53 39 31 30 30 32 00`，即 `"BS91002\0"` |
| 8 | 4 | iterations | PBKDF2 迭代次数，当前固定 200000；解密时校验范围 1 – 10000000 |
| 12 | 16 | salt | 随机盐 |
| 28 | 12 | nonce | ChaCha20 的 nonce（96 bit） |
| 40 | 2 | ext_len | 扩展名字节数 |
| 42 | `ext_len` | extension | 原始扩展名（含点，如 `.pdf`） |
| `42 + ext_len` | 8 | plain_len | 明文字节数 |
| `50 + ext_len` | `plain_len` | ciphertext | 密文 |
| `50 + ext_len + plain_len` | 32 | tag | HMAC-SHA256(文件头 ‖ 密文) |

密文总长度 = `plain_len + ext_len + 82`（固定开销 82 字节 = 50 字节头 + 32 字节 tag）。

## 工作原理

### 密钥派生

```
master = PBKDF2-HMAC-SHA256(password, salt, iterations, 32 字节)
stream = HMAC-SHA256(master, "bs9p/stream")
mac    = HMAC-SHA256(master, "bs9p/mac")
dict   = HMAC-SHA256(master, "bs9p/dict")
```

三把密钥都是 32 字节，分别用于流加密、消息认证、置换表种子。

### 置换表

把 `dict` 密钥喂给 ChaCha20（全零 nonce、counter 0）得到密钥流，用**拒绝采样**的 Fisher–Yates 洗牌生成 0–255 的置换表 `data_dict`，同时生成反查表 `reverse_dict`。

### 加密流程

1. 取输入文件的扩展名与大小，随机生成 salt / nonce，拼出文件头，并先把文件头喂给 HMAC
2. 派生密钥、重建置换表，写出文件头
3. 每 64 KiB 一块：逐字节过 `data_dict` 映射 → ChaCha20 XOR → 更新 HMAC → 写盘
4. 最后追加 32 字节 tag

### 解密流程

1. 读文件头，校验 magic 与迭代次数范围
2. 派生密钥、重建置换表
3. **完整校验 MAC**（此时还没创建输出文件）→ 不匹配就抛 `Wrong password or corrupted file`
4. `seekg` 回到密文起点，每 64 KiB 一块：ChaCha20 XOR → 过 `reverse_dict` 反查 → 写盘

## 项目结构

```
bs9p/
├── CMakeLists.txt
├── CMakePresets.json
├── CMakeUserPresets.json
├── vcpkg.json
├── vcpkg-configuration.json
├── LICENSE
├── README.md
├── include/
│   ├── chacha20.hpp      # 手写 ChaCha20 流密码
│   ├── convert.hpp       # 大端整数读写 + 定长读取
│   ├── core.hpp          # 文件头 / 编码 / 解码主流程
│   ├── data_dict.hpp     # 密钥驱动的 256 字节置换表
│   ├── fileInfo.hpp      # 路径拆解（stem / extension / parent）
│   ├── key.hpp           # 密钥派生（PBKDF2 + HMAC 扩展，OpenSSL）
│   ├── magic.hpp         # 文件魔数
│   └── sha256.hpp        # SHA-256 / HMAC-SHA256（OpenSSL EVP）
└── src/
    ├── main.cpp          # CLI11 入口
    └── res/              # Windows 图标 / 清单 / 版本信息
```

## 版本与兼容性

- 当前 `2.0.0.2`（last update 2026/10/13）
- v2 起密码是任意字符串；v1 用的是 uint32 数字种子，**与 v2 完全不兼容**
- 密文格式与加密算法自 v2 起未变；本次托管化改造（手写实现 → vcpkg 的 OpenSSL）只替换了 SHA-256 / HMAC / PBKDF2 / 随机数的底层实现，文件格式与编解码流程一行未动，ChaCha20 与置换表仍为手写实现

## 已知限制

- **不做压缩**：密文 = 明文 + `ext_len` + 82 字节
- **无法区分密码错误与文件损坏**：两者都报 `Wrong password or corrupted file`
- **没有进度显示**：大文件加密时看不到进度
- **只处理单个文件**：不支持目录递归或批量
- **不覆盖已有文件**：报 `File already exists`，需要自己先删
- **解密直接写最终文件名**：中途被强杀会留下半截明文（MAC 已在写盘前校验完，所以不会是密码错误导致的）

## 许可

[MIT](LICENSE)

## 致谢

- [CLI11](https://github.com/CLIUtils/CLI11)
- [OpenSSL](https://www.openssl.org/)
- [vcpkg](https://github.com/microsoft/vcpkg)
