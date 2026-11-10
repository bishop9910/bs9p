# bs9p

一个用 C++17 写的命令行文件加密/解密工具：把任意文件编码成 `.bs9p` 密文，支持任意字符串密码，ChaCha20 流加密 + 密钥驱动的逐字节置换 + HMAC-SHA256 认证。

## 特性

- **密码加密** —— 密码是任意字符串（不再是数字种子），PBKDF2-HMAC-SHA256 迭代 200000 轮派生密钥
- **流式处理** —— 分块读写，内存占用恒定（默认 64 KiB 一块，`--buffer-size` 可在 64 KiB – 64 MiB 之间调整），多大的文件都能处理
- **进度显示** —— 大文件（≥ 8 MiB）在交互式终端里显示百分比、已处理/总量、实时速率与 ETA；`--silent` 或输出被重定向时不显示
- **认证加密（encrypt-then-MAC）** —— HMAC-SHA256 覆盖「文件头 + 密文」，密码错 / 被篡改时不会留下任何明文
- **两层保护** —— 先按 `dict` 密钥派生的 256 字节置换表逐字节映射，再 ChaCha20 XOR
- **保留扩展名** —— 原始扩展名明文存在文件头里，解密自动还原 `report.pdf.bs9p` → `report.pdf`
- **原子写盘** —— 先写同目录临时文件、`fsync` 后用 `MoveFileEx` / `link+unlink` 一次性落位；中途断电、进程被杀都不会破坏已有文件，也不会留下半截输出
- **拒绝覆盖** —— 目标文件已存在直接报错，且「检查 + 创建」在文件系统层面是原子的，不存在 TOCTOU 覆盖窗口
- **常量时间比较** —— MAC 用 `CRYPTO_memcmp` 比较，避免计时侧信道
- **密钥擦除** —— 派生出的密钥、密码缓冲区在用完后用 `OPENSSL_cleanse` 清零

## 依赖

- **CMake** >= 3.31
- **C++17** 编译器（MSVC 19.51 / GCC）
- **vcpkg** 管理第三方库

vcpkg 依赖：

- [`CLI11`](https://github.com/CLIUtils/CLI11) —— 命令行解析
- [`OpenSSL`](https://www.openssl.org/)（libcrypto）—— ChaCha20（`EVP_chacha20`）/ SHA-256 / HMAC-SHA256 / PBKDF2 / 随机数

> ChaCha20 已改为调用 OpenSSL 的 `EVP_chacha20`（RFC 8439，自带 AVX2/AVX-512 优化），密文格式与手写实现逐字节一致，旧密文仍可解密。置换表（`include/data_dict.hpp`）仍是我们自己的逻辑，但密钥流同样来自 `EVP_chacha20`。

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

### 3. 测试

```bash
ctest --test-dir build/default -C Release --output-on-failure
```

单元测试覆盖：ChaCha20 标准测试向量与独立参考实现对比、置换表可逆性、文件头往返、多种尺寸的加解密往返（含两条解密路径）、非 ASCII 路径、`--out` / 缓冲大小两端与进度条渲染、错密码 / 篡改 / 截断 / 目标已存在 / 路径自覆盖等失败路径。

**说明**：

- `default` 预设继承 `CMakePresets.json` 里的 `msvc`；`CMakeUserPresets.json` 还会把 `VCPKG_ROOT` 直接写进预设环境（该文件已被 `.gitignore` 忽略）。
- `CMakePresets.json` 里另有 `msvc` / `gcc` / `clang` 预设，用它们时需要自己在环境里提供 `VCPKG_ROOT`。
- Windows 下本工程用静态 CRT（`CMAKE_MSVC_RUNTIME_LIBRARY = MultiThreaded`），OpenSSL 用 vcpkg `x64-windows` 的动态库，只有 `libcrypto-3-x64.dll` 需要在 exe 旁边。
- 源码是 UTF-8，MSVC 通过 `/utf-8` 编译（否则中文注释在 936 代码页下会被误解析）。
- vcpkg 走 manifest 模式，依赖装在 `build/<preset>/vcpkg_installed/` 里，不污染 `VCPKG_ROOT/installed`。
- `vcpkg-configuration.json` 的 registry 是 git 源且锁了 baseline，每次 configure 都会去 GitHub 取一次 registry 信息；本机连不上 GitHub 时先开代理，或改用本地 vcpkg checkout。

## 使用

### 基本用法

```bash
bs9p <encode|decode> [password] <input>
```

密码可以跟两个位置参数一起给，也可以省略（见下）。

| mode | 作用 |
|---|---|
| `encode` | 加密：`report.pdf` → `report.pdf.bs9p` |
| `decode` | 解密：`report.pdf.bs9p` → `report.pdf` |

### 密码的三种给法

```bash
# 1) 位置参数（注意：密码会出现在 shell 历史与进程列表里）
bs9p encode "my secret password" report.pdf

# 2) 省略密码 —— 交互式提示，输入时不回显
bs9p encode report.pdf

# 3) 从 stdin 读密码（适合脚本 / 管道）
echo "my secret password" | bs9p encode report.pdf --password-stdin
```

省略密码时：如果终端是 TTY，会提示 `Password: ` 并以 `*` 回显（不回显明文）；如果 stdin 是管道或文件，则直接读一行。

只给一个位置参数（`bs9p encode report.pdf`）时，程序把它当作输入文件，密码改为交互式询问（或配合 `--password-stdin`）。

### 进度条与输出位置

```bash
# 大文件加密：终端里（stderr 是 TTY）自动显示进度
bs9p encode "my secret password" movie.mkv
# encrypting [############............]  52.3%  4.28 GiB / 8.19 GiB  85.1 MiB/s  ETA 00:47

# 指定输出文件，或指定一个已存在的目录（沿用默认文件名）
bs9p encode "my secret password" report.pdf -o D:\backup\report.pdf.bs9p
bs9p encode "my secret password" report.pdf -o D:\backup

# 机械盘上如果觉得慢，可以试更小的缓冲（默认 64 KiB 就是机械盘的最优值）
bs9p encode "my secret password" movie.mkv -b 65536
```

进度条写在 **stderr**，所以重定向 stdout 不会污染结果；小于 8 MiB 的文件不显示（一闪而过没意义）；`-s / --silent` 时完全不显示。

> 关于缓冲大小：实测在同一块机械盘上边读边写时，**64 KiB 明显快于更大的缓冲**（大块写入会把写回打散，吞吐反而从 ~85 MiB/s 掉到 ~37 MiB/s）；SSD 上 1 MiB 只比 64 KiB 快约 7%。所以 64 KiB 是默认值，`-b` 给网络盘 / SSD 之类的场景留了调整空间。

### 非 ASCII 路径（中文 / 日文等）

Windows 下 `main` 的 `argv` 会被 CRT 按系统 ANSI 代码页（本机通常是 936）转换，`・`、`①`、部分假名之类的字符在这一步就会变成 `?`，导致路径直接失效。所以程序在 Windows 上**不使用 CRT 的 `argv`**：改为读取 `GetCommandLineW()` 的宽字符命令行，自己拆参数，全程用 UTF-8 传递，再经 `std::filesystem::u8path` 转成宽路径打开文件。带 `・`、空格、括号的日文文件名可以直接使用：

```powershell
# Windows PowerShell 5.1
.\bs9p.exe encode 'my password' '(18禁ゲームCG) [ゆずソフト] ライムライト・レモネード ジャム.7z'
# → (18禁ゲームCG) [ゆずソフト] ライムライト・レモネード ジャム.7z.bs9p
```

控制台输出也做了处理：输出到真正的控制台时用 `WriteConsoleW` 写宽字符，不会被代码页吞字；输出被重定向或走管道时，按 `GetConsoleOutputCP()` 转成控制台代码页（Windows PowerShell 5.1 按 `[Console]::OutputEncoding` 解码），没有控制台时保持 UTF-8。

文件头里的扩展名同样以 UTF-8 原样存取，所以 `.文档` 这类非 ASCII 扩展名解密后能完整还原。

### 示例

```bash
# 加密
bs9p encode "my secret password" report.pdf
# → report.pdf.bs9p

# 解密（按文件头里存的扩展名还原）
bs9p decode "my secret password" report.pdf.bs9p
# → report.pdf

# 版本 / 帮助
bs9p --version
bs9p --help
```

`--version` 输出当前版本号与最后更新日期。

## 命令行参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `mode` | 位置参数，只接受 `encode` / `decode` | 必填 |
| `password` | 位置参数，密码，任意字符串 | 省略则交互式询问 |
| `input` | 位置参数，输入文件路径 | 必填 |
| `-o, --out` | 输出文件路径；给一个已存在的目录则把默认文件名放进去 | 默认命名 |
| `-b, --buffer-size` | IO 缓冲字节数，范围 65536 – 67108864 | `65536`（64 KiB） |
| `--password-stdin` | 从标准输入读一行作为密码 | 关闭 |
| `-s, --silent` | 成功时不打印提示 | 关闭 |
| `-h, --help` | 显示帮助并退出 | — |
| `-v, --version` | 显示版本并退出 | — |

位置参数按顺序匹配；参数不合法或缺参数时 CLI11 打印错误与退出码，运行时错误打到 stderr，成功返回 `0`、失败返回非 `0`。

## 文件格式

所有整数**大端**存储。文件头（`header.raw`）就是 HMAC 覆盖的前半段：

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 8 | magic | `42 53 39 50 31 30 34 00`，即 `"BS9P104\0"` |
| 8 | 4 | iterations | PBKDF2 迭代次数，当前固定 200000；解密时校验范围 1 – 10000000 |
| 12 | 16 | salt | 随机盐 |
| 28 | 12 | nonce | ChaCha20 的 nonce（96 bit） |
| 40 | 2 | ext_len | 扩展名字节数 |
| 42 | `ext_len` | extension | 原始扩展名（含点，如 `.pdf`） |
| `42 + ext_len` | 8 | plain_len | 明文字节数 |
| `50 + ext_len` | `plain_len` | ciphertext | 密文 |
| `50 + ext_len + plain_len` | 32 | tag | HMAC-SHA256(文件头 ‖ 密文) |

密文总长度 = `plain_len + ext_len + 82`（固定开销 82 字节 = 50 字节头 + 32 字节 tag）。

解密前会做这些一致性检查，任何一项不满足都直接拒绝（不会创建任何输出文件）：

- magic 必须匹配，`iterations` 必须在合法范围内
- 扩展名长度 ≤ 255、必须以 `.` 开头、不能含路径分隔符 / Windows 保留字符 / 控制字符（防止 `ext` 里塞 `../` 之类的路径穿越）
- `plain_len` 不能超过 ChaCha20 计数器能产生的密钥流上限（约 256 GiB）
- `header.size + plain_len + 32` 必须等于文件实际大小（拒绝被截断或尾部追加的密文）
- 解密输出路径不能和输入文件是同一个文件

## 工作原理

### 密钥派生

```
master = PBKDF2-HMAC-SHA256(password, salt, iterations, 32 字节)
stream = HMAC-SHA256(master, "bs9p/stream")
mac    = HMAC-SHA256(master, "bs9p/mac")
dict   = HMAC-SHA256(master, "bs9p/dict")
```

三把密钥都是 32 字节，分别用于流加密、消息认证、置换表种子。`master` 与三把子密钥在用完后都会清零。

### 置换表

把 `dict` 密钥喂给 ChaCha20（全零 nonce、counter 0）得到密钥流，用**拒绝采样**的 Fisher–Yates 洗牌生成 0–255 的置换表，同时生成反查表。两张表属于单次加解密实例（不共享全局状态），用完清零。

### 加密流程

1. 取输入文件的扩展名与大小，随机生成 salt / nonce，拼出文件头，并先把文件头喂给 HMAC
2. 派生密钥、重建置换表，在目标同目录创建临时文件并写出文件头
3. 每块（默认 64 KiB，`--buffer-size` 可调）：逐字节过置换表映射 → ChaCha20 XOR → 更新 HMAC → 写临时文件
4. 追加 32 字节 tag，`fsync`，然后原子改名到最终路径（已存在则失败，不覆盖）

### 解密流程

1. 读文件头，校验 magic、迭代次数、扩展名，并核对文件大小
2. 派生密钥、重建置换表
3. 按明文大小分两条路径：
   - **≤ 128 MiB**：整体解到内存，先验证 MAC 再一次性写临时文件 → 原子落位。只读一遍密文，且验证失败时磁盘上不会出现任何东西
   - **> 128 MiB**：边解密边写临时文件，同时计算 MAC；MAC 不匹配就删掉临时文件并报错。只读一遍密文，代价是验证前临时文件里已有明文
4. 临时文件 `fsync` 后原子改名到最终路径

两条路径都不会覆盖已存在的文件，也都会在失败时清理临时文件。

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
│   ├── atomic_file.hpp   # 临时文件 + fsync + 原子改名
│   ├── chacha20.hpp      # ChaCha20（OpenSSL EVP_chacha20 封装）
│   ├── convert.hpp       # 大端整数读写 + 定长读取
│   ├── core.hpp          # 文件头 / 编码 / 解码主流程
│   ├── data_dict.hpp     # 密钥驱动的 256 字节置换表
│   ├── fileInfo.hpp      # 路径拆解（stem / extension / parent）
│   ├── key.hpp           # 密钥派生（PBKDF2 + HMAC 扩展，OpenSSL）
│   ├── magic.hpp         # 文件魔数
│   ├── path_util.hpp     # UTF-8 字符串 <-> 文件系统路径（Windows 走宽字符）
│   ├── progress.hpp      # 终端进度条（stderr，TTY 才显示）
│   ├── secure.hpp        # 敏感数据擦除（OPENSSL_cleanse）
│   └── sha256.hpp        # SHA-256 / HMAC-SHA256（OpenSSL EVP）
├── src/
│   ├── main.cpp          # CLI11 入口 + 密码读取
│   └── res/              # Windows 图标 / 清单 / 版本信息
└── tests/
    ├── CMakeLists.txt
    └── test_bs9p.cpp     # 单元测试
```

## 版本与兼容性

- 具体版本号以 `bs9p --version` 为准
- v2 起密码是任意字符串；v1 用的是 uint32 数字种子，**完全不兼容**
- 1.0.4 的容器布局、密钥派生、置换表算法沿用改造前的实现，只把 ChaCha20 换成 OpenSSL `EVP_chacha20`（逐字节等价）并把 magic 升到 `BS9P104`
- magic 自 1.0.4 起为 `BS9P104`；1.0.3 的 `BS9P103` 与更早的 `BS91002` 密文不再支持（这些版本都没对外发布，不做兼容读取）

## 已知限制

- **没有压缩**：密文 = 明文 + `ext_len` + 82 字节
- **无法区分密码错误与文件损坏**：两者都报 `Wrong password or corrupted file`
- **只处理单个文件**：不支持目录递归或批量
- **不覆盖已有文件**：报 `File already exists`，需要自己先删
- **超大文件解密会在验证前写明文**：> 128 MiB 的文件为了只读一遍密文，临时文件在 MAC 验证完成前就包含解密结果（失败会删除）
- **控制台只做了 Windows 的处理**：Linux / macOS 直接按 UTF-8 字节输出，终端 locale 不是 UTF-8 时可能显示异常（文件名本身不受影响）

## 许可

[MIT](LICENSE)

## 致谢

- [CLI11](https://github.com/CLIUtils/CLI11)
- [OpenSSL](https://www.openssl.org/)
- [vcpkg](https://github.com/microsoft/vcpkg)
