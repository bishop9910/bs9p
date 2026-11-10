# 加密流程（encode）

本文按**执行顺序**拆解 `bs9p encode` 做的每一件事：做了哪些检查、密钥怎么来的、置换表怎么生成、主循环里每块数据的处理顺序、最后如何安全落盘。

- 密文的字段布局见 [文件数据结构](file-format.md)
- 反方向（解密）见 [解密流程](decryption.md)
- 命令行用法见 [根 README](../README.md)

实现入口：[`include/core.hpp`](../include/core.hpp) 的 `bs9::encode_file()`。

## 1. 入口与参数

```
bs9p encode [password] <input> [-o <文件或目录>] [-b <缓冲字节数>] [-s]
```

| 参数 | 作用 |
|---|---|
| `password` | 密码，UTF-8 字节直接参与 PBKDF2；省略时交互式不回显读取，或用 `--password-stdin` 从管道读 |
| `<input>` | 输入文件路径（含非 ASCII 字符也可，内部全程 UTF-8） |
| `-o, --out` | 输出文件；给已存在目录则把默认文件名放进该目录 |
| `-b, --buffer-size` | 主循环缓冲，64 KiB – 64 MiB，默认 64 KiB |
| `-s, --silent` | 不打印成功/失败之外的信息，也不显示进度条 |

加密**只读**输入文件，**从不修改**它。

## 2. 前置检查

全部在创建任何文件之前完成，任何一条失败都不会留下垃圾：

| 顺序 | 检查 | 失败信息 |
|---|---|---|
| 1 | 输出路径不能就是输入路径 | `Output file would overwrite the input file: <path>` |
| 2 | 输出文件不能已存在 | `File already exists: <path>` |
| 3 | 读取输入大小（同时确认文件可访问） | `Failed to read input file size: <path> (<系统错误>)` |
| 4 | `plain_len ≤ 2^38`（256 GiB，ChaCha20 计数器上限） | `File is too large for ChaCha20 (limit is 256 GiB): <path>` |
| 5 | 以二进制模式打开输入流 | `Failed to open input file: <path>` |

第 1 条防的是 `-o` 指到输入自己；第 2 条防覆盖，最终落位时还会再防一次（见 §9）。

随后把输入流设为 `exceptions(badbit)`：读错误会抛异常，而不是静默产生一个短密文。

## 3. 构造文件头

`plain_len` 已经知道，扩展名从输入文件名取（UTF-8，含前导点）：

```cpp
const bs9::Header header = bs9::make_header(bs9::parse_file(in).extension, plain_len);
```

`make_header` 依次做：

1. `validate_extension()` 净化扩展名（长度、前导点、控制字符、路径分隔符）
2. `random_bytes(salt, 16)`、`random_bytes(nonce, 12)` —— 每文件都重新生成
3. `iterations = PBKDF2_ITERATIONS = 200000`
4. 按 [文件数据结构 §2](file-format.md#2-文件头字段表) 的顺序拼成 `header.raw`（50 + E 字节）

`header.raw` 会被**原样**写入密文开头，并且**参与 MAC**——所以解密端解析出的头部必须逐字节还原，否则标签对不上。

## 4. 密钥派生

```
master  = PBKDF2-HMAC-SHA256(password, salt, iterations = 200000, dkLen = 32)
stream  = HMAC-SHA256(master, "bs9p/stream")
mac     = HMAC-SHA256(master, "bs9p/mac")
dict    = HMAC-SHA256(master, "bs9p/dict")
```

要点：

- 三把子密钥**互相独立**：即使某个用途的密钥流被分析，也推不出另外两把
- 标签是固定 ASCII 字面量，直接作为 HMAC 的消息
- `master` 用完立即擦除（`CleanseGuard` 出作用域触发 `OPENSSL_cleanse`）
- `KeySet` 析构时擦除三把子密钥，禁止拷贝（避免擦除漏掉副本）

代码：[`include/key.hpp`](../include/key.hpp) 的 `derive_keys()`。

PBKDF2 让每次尝试都要付出 200000 轮 SHA-256 的代价（约 20 ms），暴力猜测密码的成本由此抬高；`salt` 保证同一密码在不同文件上得到不同 `master`。

## 5. 置换表

`dict` 子密钥派生出一张 256 字节的双向置换表：

```
keystream = ChaCha20(key = dict, nonce = 0^12, counter = 0)

values[i] = i                       (i = 0..255)
for i = 255 down to 1:
    limit = 256 - (256 % (i + 1))            // 拒绝采样，消除取模偏差
    do { b = next keystream byte } while (b >= limit)
    swap(values[i], values[b % (i + 1)])

forward[x]  = values[x]                      // 正向：明文 → 置换后
reverse[forward[x]] = x                      // 反向：置换后 → 明文
```

- 这是一个由密钥决定的 **Fisher-Yates 洗牌**，等价于随机置换
- 拒绝采样保证 `b % (i+1)` 在 `0..i` 上均匀分布，否则小下标会被轻微偏爱
- 表只依赖 `dict` 密钥，与 `nonce`、文件内容无关，因此同一密码 + 同一 salt 得到同一张表——这也是格式兼容性的基础
- 表在 `DataDict` 析构时擦除

代码：[`include/data_dict.hpp`](../include/data_dict.hpp)。

> 这张表不提供额外的密码学强度（它是公开可推导的置换，密钥已知即可复现）。它的作用是让密文在 XOR 之前先被打散，属于本格式的设计选择，不能当作独立的安全层。

## 6. 初始化 MAC 与输出

```cpp
bs9::HmacSha256 mac(keys.mac.data(), keys.mac.size());
mac.update(header.raw.data(), header.raw.size());   // 头部先进 MAC

bs9::AtomicOutput output(out);                      // 同目录临时文件
std::ostream& ofs = output.stream();
ofs.write(header.raw.data(), header.raw.size());     // 头部先落盘
```

`AtomicOutput` 在目标同目录创建 `<目标文件名>.tmp-<16 位随机 hex>`，并把输出流设为 `exceptions(failbit | badbit)`：磁盘写满、权限变化、句柄失效都会抛异常，不会静默截断。

## 7. 主循环

```
ChaCha20 stream(keys.stream, header.nonce, counter = 0)
buffer = clamp_buffer_size(io.buffer_size)     // 默认 64 KiB

while 还有明文:
    读取至多 buffer.size() 字节明文
    for 每个字节: buffer[i] = forward[buffer[i]]   // ① 查表置换
    stream.xor_data(buffer, chunk)                 // ② XOR 密钥流（原地）
    mac.update(buffer, chunk)                      // ③ MAC 吃的是密文
    写入临时文件                                    // ④
    更新进度条
```

顺序是格式的一部分：

- **① 必须在 ② 之前**：密文 = `keystream XOR forward_table[plaintext]`
- **③ 必须在 ② 之后**：标签覆盖的是**密文**（encrypt-then-MAC），不是明文
- **④ 只是落盘**，不影响密码学结果

`ChaCha20` 是 [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) 的 IETF 变体（32 bit 计数器 + 96 bit nonce），由 OpenSSL `EVP_chacha20` 实现。密钥流从 `counter = 0` 开始，整文件用**同一条**流；`chacha_max_bytes(0) = 256 GiB`，超过会在 §2 第 4 条被拒。`xor_data` 内部按 ≤ 1 GiB 分片调用 EVP（避免 `int` 长度溢出），并累计已用字节数，超出容量直接抛 `ChaCha20 counter overflow`。

## 8. 收尾：标签与落位

```cpp
const bs9::Digest tag = mac.final();          // HMAC-SHA256，32 字节
ofs.write(tag.data(), tag.size());
output.commit();
```

`commit()` 的顺序（[`include/atomic_file.hpp`](../include/atomic_file.hpp)）：

| 步骤 | Windows | POSIX |
|---|---|---|
| 1 | `ofs.flush()` + `close()` | 同左 |
| 2 | 以 `GENERIC_WRITE` 打开临时文件，`FlushFileBuffers` | `open(O_RDONLY)` + `fsync` |
| 3 | `MoveFileExW(temp, target, MOVEFILE_WRITE_THROUGH)`（**不带** `MOVEFILE_REPLACE_EXISTS`） | `link(temp, target)` + `unlink(temp)`（`EEXIST` 即失败） |
| 4 | —（`WRITE_THROUGH` 已覆盖目录项） | `fsync` 父目录 |

因此目标路径只有两种状态：**不存在**，或**完整密文**。中途断电、进程被杀、磁盘写满，都不会留下半个 `.bs9p`。

## 9. 失败时的不变量

| 场景 | 结果 |
|---|---|
| 密码错（只影响解密，不影响加密） | — |
| 目标已存在 | 抛异常，原文件字节不变 |
| 磁盘写满 / 写失败 | 抛异常，临时文件被析构删除，目标路径不变 |
| 进程被强杀 / 断电 | 最多留下 `<目标>.tmp-<hex>`，目标路径不出现半成品；下次加密不会误用它 |
| 输入在读的过程中变化（被别的程序改写） | 读出多少算多少，标签与 `plain_len` 仍自洽；不保证与"当时的输入"一致 |

**输入文件永远只读**，任何失败都不会损坏它。

## 10. 性能

密码学部分在 CPU 上并不慢（本机实测，1 GiB 热缓冲区）：

| 阶段 | 吞吐 |
|---|---|
| 置换表查表 | ~6.3 GiB/s |
| ChaCha20（EVP） | ~4.9 GiB/s |
| HMAC-SHA256（EVP） | ~4.4 GiB/s |
| 三者合计（理论） | ~1.7 GiB/s |

也就是说 8 GB 文件的密码学开销约 5 秒；实际速度由**磁盘**决定。同盘边读边写时，机械盘（尤其 SMR）的瓶颈非常明显：缓冲从 64 KiB 加到 4 MiB，实测吞吐反而从 ~85 MiB/s 掉到 ~37 MiB/s。因此默认缓冲是 **64 KiB**，需要时用 `--buffer-size` 覆盖。

进度条（stderr，仅在终端且未加 `-s` 时显示）会给出百分比、已处理/总量、实时速率与 ETA；小于 8 MiB 的文件不显示。

## 11. 步骤速查

```
1  检查输出 ≠ 输入、输出不存在
2  plain_len = 文件大小；> 256 GiB 直接拒绝
3  生成 salt(16) / nonce(12)，拼 header.raw（magic + iterations + salt + nonce + ext + plain_len）
4  master = PBKDF2-SHA256(password, salt, 200000)
   stream/mac/dict = HMAC-SHA256(master, "bs9p/{stream,mac,dict}")
5  DataDict = Fisher-Yates(forward/reverse) ← ChaCha20(dict, 0^12, 0)
6  mac.update(header.raw)；写出 header.raw 到临时文件
7  逐块：读 → 查 forward → XOR 密钥流 → mac.update(密文) → 写临时文件
8  tag = mac.final()；写出 tag
9  flush → fsync → 原子改名（不覆盖）→（POSIX）fsync 目录
```

## 12. 相关代码

| 步骤 | 位置 |
|---|---|
| CLI 参数、密码读取、进度条开关 | [`src/main.cpp`](../src/main.cpp) |
| 前置检查、主循环、标签 | [`include/core.hpp`](../include/core.hpp) `encode_file()` |
| 头部构造 | [`include/core.hpp`](../include/core.hpp) `make_header()` / `validate_extension()` |
| 密钥派生 | [`include/key.hpp`](../include/key.hpp) `derive_keys()` |
| 置换表 | [`include/data_dict.hpp`](../include/data_dict.hpp) |
| ChaCha20 | [`include/chacha20.hpp`](../include/chacha20.hpp) |
| HMAC-SHA256 | [`include/sha256.hpp`](../include/sha256.hpp) |
| 进度条 | [`include/progress.hpp`](../include/progress.hpp) |
| 原子落位 | [`include/atomic_file.hpp`](../include/atomic_file.hpp) |
