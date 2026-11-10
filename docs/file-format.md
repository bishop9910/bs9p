# 文件数据结构（密文格式）

本文是 `.bs9p` 密文的**二进制规格说明**：每个字段在哪、多长、什么字节序、有什么约束、MAC 覆盖到哪。

- 面向实现者 / 需要自己解析密文的场景
- 只想用命令行的话看 [根 README](../README.md) 即可
- 加解密每一步做了什么，见 [加密流程](encryption.md) 与 [解密流程](decryption.md)

当前格式版本：**1.0.4**，magic `BS9P104`。

## 1. 总体布局

密文是一个**扁平文件**，没有任何容器嵌套、没有压缩、没有填充：

```
+----------------+---------------------+------------------+
|    header      |      ciphertext     |       tag        |
|  50 + E 字节   |      P 字节         |      32 字节     |
+----------------+---------------------+------------------+
^                                                       ^
文件开头                                            文件结尾
```

- `E` = `ext_len`，扩展名字节数（0 – 255）
- `P` = `plain_len`，**原始明文**字节数（也是密文字节数，流加密不改变长度）
- 总长度恒为 `P + E + 82`（82 = 50 字节固定头 + 32 字节 tag）

**字节序**：所有整数一律**大端**（network order）。代码见 [`include/convert.hpp`](../include/convert.hpp) 的 `append_uintNN` / `load_uintNN`。

## 2. 文件头字段表

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| `0` | 8 | `magic` | 8 字节字面量 | `42 53 39 50 31 30 34 00`，即 `"BS9P104\0"` |
| `8` | 4 | `iterations` | uint32 BE | PBKDF2 迭代次数，加密时固定写 `200000` |
| `12` | 16 | `salt` | 16 字节随机 | PBKDF2 的盐，每个文件重新生成 |
| `28` | 12 | `nonce` | 12 字节随机 | ChaCha20 的 96 bit nonce，每个文件重新生成 |
| `40` | 2 | `ext_len` | uint16 BE | 扩展名字节数 `E`，合法范围 0 – 255 |
| `42` | `E` | `extension` | UTF-8 字节 | 原始扩展名，**包含前导点**，如 `.pdf`；无扩展名时 `E = 0` |
| `42 + E` | 8 | `plain_len` | uint64 BE | 原始明文字节数 `P` |
| — | — | — | — | 头部到 `50 + E` 结束 |

`header.size = 50 + E`，这个值同时决定密文正文从哪个偏移开始。

### magic

`magic` 是格式与版本的双重标识，**必须逐字节精确匹配**，否则直接拒绝：

```
 Error: Magic mismatch: not a bs9p file, or it was made by an incompatible version
```

历史值（均已不支持，且从未对外发布）：

| 版本 | magic |
|---|---|
| 2.0.0.x | `BS91002\0` |
| 1.0.3 | `BS9P103\0` |
| **1.0.4（当前）** | **`BS9P104\0`** |

换 magic 意味着**旧密文无法解密**，这是有意的：格式的语义保证只对当前版本成立。

### iterations

PBKDF2-HMAC-SHA256 的迭代次数。写入端固定用 [`include/core.hpp`](../include/core.hpp) 的 `PBKDF2_ITERATIONS = 200000`；读取端接受 `1 – 10000000`，越界报 `Invalid iteration count in header`。

之所以把这个字段放在头里而不是写死，是为了让未来提高默认轮数时，旧密文仍能按它自己的轮数解密。它是一个**成本参数**，不属于秘密。

### salt 与 nonce

都是每个文件重新生成的随机值（`RAND_bytes`，见 [`include/key.hpp`](../include/key.hpp)）：

- `salt` 让同一密码在不同文件上派生出不同密钥，防止彩虹表 / 跨文件密钥复用
- `nonce` 让同一条 ChaCha20 密钥流不会重复使用

两者都是**公开的**，写在头里不会削弱安全性；它们不需要保密，只需要唯一。

### extension

原始文件名「最后一个点之后的部分」，UTF-8 编码，带前导点：

| 原文件名 | `extension` |
|---|---|
| `report.pdf` | `.pdf` |
| `archive.tar.gz` | `.gz` |
| `(18禁ゲームCG) ライムライト・レモネード.7z` | `.7z`（宽字符按 UTF-8 存） |
| `README` | 空，`E = 0` |
| `中文・文件名.文档` | `.文档`（UTF-8 多字节扩展名） |

读取端会做**净化**（[`validate_extension`](../include/core.hpp)），因为扩展名会被拼进输出路径，而文件头在验 MAC 之前是不可信的：

- 长度 ≤ 255 字节
- 首字节必须是 `.`（空扩展名除外）
- 不允许控制字符（`< 0x20`、`0x7F`）
- 不允许 `/` `\` `:` `*` `?` `"` `<` `>` `|`（防止 `../` 之类的路径穿越）

任何一条不满足，解密在创建任何输出文件之前就会失败。

### plain_len

原始明文字节数。它决定要读多少密文、也决定解密时分配多少内存，因此有两道校验：

1. `plain_len ≤ chacha_max_bytes(0) = 2^32 × 64 = 2^38 字节 = 256 GiB`
   —— ChaCha20 的 32 bit 计数器最多产出这么多密钥流，超过就无法用单条流覆盖
2. `header.size + plain_len + 32` 必须**精确等于**文件实际大小
   —— 拒绝被截断、尾部追加、或头部长度被篡改的密文

## 3. 密文正文

`ciphertext` 长度恰好 `P` 字节，逐字节定义为：

```
ciphertext[i] = ChaCha20_keystream(stream_key, nonce, counter=0)[i]
                XOR forward_table[ plaintext[i] ]
```

其中 `forward_table` 是由 `dict` 子密钥生成的 256 字节置换表（生成算法见 [加密流程 §5](encryption.md#5-置换表)）。

注意顺序：**先查表置换，再 XOR 密钥流**。解密必须反着来：**先 XOR，再查反查表**。

流加密的密文与明文等长，没有块对齐、没有填充，所以空文件（`P = 0`）的正文段长度为 0。

## 4. 认证标签

文件最后 32 字节：

```
tag = HMAC-SHA256(key = mac_key,
                  data = header 的全部字节 ‖ ciphertext 的全部字节)
```

- 覆盖范围是**头部 + 密文**，不含 tag 自身
- 覆盖的是**密文**，不是明文（encrypt-then-MAC）
- 用 OpenSSL 的 `EVP_MAC`（HMAC + SHA-256）计算，见 [`include/sha256.hpp`](../include/sha256.hpp)
- 比较用 `CRYPTO_memcmp`（常量时间），避免计时侧信道

三项密钥（`stream` / `mac` / `dict`）彼此独立，由 PBKDF2 的 master 经 HMAC 打标签扩展得到，见 [加密流程 §4](encryption.md#4-密钥派生)。

## 5. 完整示例

用密码 `demo` 加密一个 6 字节文件 `hello.txt`（内容 `hello\n`）：

```powershell
.\bs9p.exe encode demo hello.txt
# → hello.txt.bs9p（92 字节 = 6 + 4 + 82）
```

实际字节（每行 16 字节，左侧为十六进制偏移）：

```
0000  42 53 39 50 31 30 34 00 00 03 0d 40 a1 6a 8c 4e
0010  25 b1 4e 9f ef 46 7c a6 af 2c b3 64 d1 c0 3b fe
0020  c5 34 0b 06 52 6f 23 9a 00 04 2e 74 78 74 00 00
0030  00 00 00 00 00 06 1a 8d 73 1d 5c 7e 3d 99 1a c0
0040  67 36 1e 79 1d ef 1b eb 22 5c 75 0c 43 77 a1 4a
0050  85 af 85 23 0b 21 1f 5a 4a 4d af fe
```

逐字段解释：

| 偏移 | 字节 | 字段 | 解读 |
|---|---|---|---|
| `0x00` | `42 53 39 50 31 30 34 00` | magic | `"BS9P104\0"` |
| `0x08` | `00 03 0d 40` | iterations | `200000` |
| `0x0c` | `a1 6a 8c 4e 25 b1 4e 9f ef 46 7c a6 af 2c b3 64` | salt | 16 字节随机 |
| `0x1c` | `d1 c0 3b fe c5 34 0b 06 52 6f 23 9a` | nonce | 12 字节随机 |
| `0x28` | `00 04` | ext_len | `4` |
| `0x2a` | `2e 74 78 74` | extension | `".txt"` |
| `0x2e` | `00 00 00 00 00 00 00 06` | plain_len | `6` |
| `0x36` | `1a 8d 73 1d 5c 7e` | ciphertext | 6 字节 |
| `0x3c` | `3d 99 … af fe` | tag | 32 字节 HMAC |

`0x36 = 54 = 50 + 4`，验证了正文起点等于 `header.size`。

## 6. 尺寸速查

| 场景 | 头部 | 总大小 |
|---|---|---|
| 无扩展名，空文件 | 50 | 82 |
| 无扩展名，`P` 字节 | 50 | `P + 82` |
| `.txt`（4 字节），空文件 | 54 | 86 |
| `.pdf`（4 字节），`P` 字节 | 54 | `P + 86` |
| `.tar.gz` 取最后一个 `.gz`（3 字节） | 53 | `P + 85` |

## 7. 解析伪代码

```cpp
read 8 bytes  -> magic       // 不等于 "BS9P104" 就直接失败
read 4 bytes  -> iterations  // 1 <= iterations <= 10'000'000
read 16 bytes -> salt
read 12 bytes -> nonce
read 2 bytes  -> ext_len     // 0 <= ext_len <= 255
read ext_len  -> extension   // 校验：以 '.' 开头、无分隔符/控制字符、<= 255 字节
read 8 bytes  -> plain_len   // <= 2^38
// 校验：50 + ext_len + plain_len + 32 == 文件大小
read plain_len -> ciphertext
read 32 bytes  -> tag
// 校验：HMAC-SHA256(mac_key, header || ciphertext) == tag
```

任何一步长度不足都会得到 `Unexpected end of file`；任何一步校验失败都会在**创建输出文件之前**终止。

## 8. 相关代码

| 关注点 | 文件 |
|---|---|
| 魔数常量 | [`include/magic.hpp`](../include/magic.hpp) |
| 字段拼装 / 解析 / 校验 | [`include/core.hpp`](../include/core.hpp)（`make_header` / `read_header` / `validate_layout`） |
| 大端读写与定长读取 | [`include/convert.hpp`](../include/convert.hpp) |
| 密钥派生与 HMAC 扩展 | [`include/key.hpp`](../include/key.hpp) |
| 置换表 | [`include/data_dict.hpp`](../include/data_dict.hpp) |
| ChaCha20（EVP 封装） | [`include/chacha20.hpp`](../include/chacha20.hpp) |
| HMAC-SHA256 | [`include/sha256.hpp`](../include/sha256.hpp) |
| 原子落位 | [`include/atomic_file.hpp`](../include/atomic_file.hpp) |
