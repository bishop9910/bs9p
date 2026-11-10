# 解密流程（decode）

本文按**执行顺序**拆解 `bs9p decode`：先解析并校验头部，再派生密钥，然后按文件大小走两条不同的路径，最后验证 HMAC 并原子落位。

- 密文字段布局见 [文件数据结构](file-format.md)
- 反方向（加密）见 [加密流程](encryption.md)
- 命令行用法见 [根 README](../README.md)

实现入口：[`include/core.hpp`](../include/core.hpp) 的 `bs9::decode_file()`。

## 1. 入口与参数

```
bs9p decode [password] <input.bs9p> [-o <文件或目录>] [-b <缓冲字节数>] [-s]
```

满足以下任一条件时，解密还需要 `-o` 指定输出（否则可能撞上"输出=输入"或"文件已存在"）：

- 密文被改过名，还原出的原文件名与某个已有文件冲突
- 你希望解到另一个目录

## 2. 读头部并校验

`read_header()` 逐字段读取，**每一步失败都在创建输出文件之前终止**：

| 顺序 | 动作 | 失败信息 |
|---|---|---|
| 1 | 读 42 字节固定段 | `Unexpected end of file`（文件太短） |
| 2 | 比较 magic（必须 `BS9P104\0`） | `Magic mismatch: not a bs9p file, or it was made by an incompatible version` |
| 3 | `iterations` 必须在 `1 – 10000000` | `Invalid iteration count in header` |
| 4 | 拷贝 `salt`、`nonce` | — |
| 5 | 读 `ext_len`，再读该长度的扩展名 | `Unexpected end of file` |
| 6 | 净化扩展名（前导点 / 控制字符 / 路径分隔符 / ≤255） | `Stored extension ...` |
| 7 | 读 `plain_len` | `Unexpected end of file` |

与此同时，读到的每个字节都被追加进 `header.raw`——它必须与加密端写下的头部**逐字节一致**，因为 HMAC 覆盖的就是这段原始字节。

> 为什么在验 MAC **之前**就严格校验？
> 因为 MAC 本身需要 `plain_len` 才知道要读多少密文、需要扩展名才知道往哪写。所以头部是"先校验、后认证"的：所有能提前判定的结构性约束（magic、迭代次数范围、扩展名白名单、长度上限、文件大小吻合）都必须先做，否则一个恶意头部就能让程序去分配 256 GiB 内存、或把明文写到目录外。

### 布局校验

读到 `plain_len` 之后，立刻用实际文件大小交叉验证：

```cpp
if (header.plain_len > chacha_max_bytes(0))  // > 2^38 = 256 GiB
    throw "Invalid plaintext length in header: too large for ChaCha20";
if (header.size + header.plain_len + TAG_LEN != file_size)
    throw "File size mismatch: header expects N bytes, file has M";
```

这一条同时挡住：被截断的密文、尾部被追加数据的密文、`plain_len` 被改大的攻击、以及"头里声明 200 GB 但文件只有 2 KB"的 DoS。

## 3. 还原输出文件名

密文名的约定是「原文件名 + `.bs9p`」，所以先尝试去掉后缀：

| 输入 | `header.extension` | 输出 |
|---|---|---|
| `report.pdf.bs9p` | `.pdf` | `report.pdf`（去掉 `.bs9p` 后已带 `.pdf`，不再追加） |
| `report.pdf.bs9p` | 空 | `report.pdf` |
| `cipher.bs9p` | `.pdf` | `cipher.pdf`（去后缀后没有原扩展名，补回） |
| `backup.bs9p`（被改过名） | `.txt` | `backup.txt` |
| `archive.bs9p.bs9p` | `.7z` | `archive.bs9p.7z` |

规则：

1. 若输入名以 `.bs9p` 结尾（区分大小写），去掉这 5 个字符
2. 否则退回到 `parent_path / stem`（即去掉最后一个扩展名）
3. 若 `header.extension` 非空且当前名字**还不是**以它结尾，追加

第 3 步的"已结尾则不追加"很关键：新格式的密文名自带原扩展名（`doc.pdf.bs9p`），无条件追加会得到 `doc.pdf.pdf`。

最后 `-o` 若给的是已存在目录，则把上面算出的文件名放进该目录。

## 4. 安全检查

| 检查 | 失败信息 |
|---|---|
| 输出路径不能等于输入路径（防止把密文覆盖掉） | `Output file would overwrite the input file: <path>` |
| 输出文件不能已存在 | `File already exists: <path>` |

比较用 `weakly_canonical`（失败退 `absolute`），能识别 `./a.bin` 与 `a.bin` 这类写法差异。

> 这一步是必要的：如果密文头里记录的扩展名恰好是 `.bs9p`，或密文被改名成 `report.pdf` 再解密，还原出的输出名可能正是输入自己。真写下去就先把密文毁了。

## 5. 派生密钥与 MAC 初始化

与加密端完全相同的三步：

```
master = PBKDF2-HMAC-SHA256(password, header.salt, header.iterations)   // 注意用头里的轮数
stream = HMAC-SHA256(master, "bs9p/stream")
mac    = HMAC-SHA256(master, "bs9p/mac")
dict   = HMAC-SHA256(master, "bs9p/dict")
```

然后：

```cpp
DataDict dict(keys.dict.data());          // 重建置换表（同一密钥 → 同一张表）
HmacSha256 mac(keys.mac.data(), ...);
mac.update(header.raw.data(), header.raw.size());   // 头部先进 MAC
```

`iterations` 取自文件头而不是写死 200000，这样未来提高默认轮数时旧密文仍可解。

## 6. 两条解密路径

`plain_len ≤ MEMORY_DECRYPT_LIMIT`（默认 **128 MiB**）走内存路径，否则走流式路径。两条路径都**只读一遍密文**。

### 6.1 小文件：先解密到内存，验证后才落盘

```
data = vector(plain_len)                 // 加 CleanseGuard，退出时擦除
loop: 读一块密文 → mac.update(密文)       // 密文进 MAC
读 32 字节 tag
computed = mac.final()
constant-time 比较 tag：
    不等 → 抛 "Wrong password or corrupted file"（此时磁盘上还没有任何输出）
    相等 → ChaCha20.xor_data(data) → data[i] = reverse[data[i]]
写 data 到临时文件 → commit
```

优点：**密码错时磁盘上完全不出现明文**，连临时文件都没有。
代价：明文要整体驻留内存（上限 128 MiB）。

### 6.2 大文件：边解密边写临时文件

```
创建 AtomicOutput（临时文件）
loop: 读一块密文 → mac.update(密文) → XOR 密钥流 → 查 reverse 表 → 写临时文件 → 进度
读 32 字节 tag
computed = mac.final()
constant-time 比较 tag：
    不等 → 抛异常；AtomicOutput 析构删除临时文件，目标路径不出现
    相等 → commit（flush → fsync → 原子改名）
```

优点：内存占用恒定（一个缓冲）。
代价：验证之前明文已经写进临时文件；失败时靠析构把临时文件删掉（断电时可能残留 `<目标>.tmp-<hex>`，但**目标路径**上不会出现半成品）。

### 两条路径对比

| | 小文件（≤ 128 MiB） | 大文件（> 128 MiB） |
|---|---|---|
| 内存 | 明文大小 | 一个缓冲（默认 64 KiB） |
| 读密文次数 | 1 | 1 |
| 验证前是否有明文落盘 | **没有** | 临时文件里有 |
| 密码错时的痕迹 | 无 | 临时文件被删除 |
| 断电 | 无输出 | 可能残留 `.tmp-<hex>`，目标不存在 |

阈值是 `decode_file` 的参数（默认 `MEMORY_DECRYPT_LIMIT`），测试会用两条路径各跑一遍。

## 7. 解密运算的顺序

与加密严格互逆：

```
加密： ciphertext = keystream XOR forward[plaintext]
解密： plaintext  = reverse[keystream XOR ciphertext]
```

即：**先 XOR 密钥流，再查反查表**。顺序写反了（先查表再 XOR）会得到乱码，而且 MAC 仍然通过——因为 MAC 只看密文，所以这类错误只能靠往返测试发现。

`ChaCha20` 解密与加密是同一个操作（流密码），`EVP_EncryptUpdate` 直接复用。

## 8. 错误信息对照

| 错误信息 | 含义 |
|---|---|
| `Failed to open input file: <path>` | 文件不存在 / 无权限 / 是目录 |
| `Unexpected end of file` | 头部或正文不完整（截断） |
| `Magic mismatch: not a bs9p file, or it was made by an incompatible version` | 不是本格式，或旧版本（BS91002 / BS9P103） |
| `Invalid iteration count in header` | 头部里的迭代次数为 0 或 > 10000000 |
| `Stored extension is too long` / `does not start with a dot` / `contains a control character` / `contains a path separator or reserved character` | 扩展名未通过净化 |
| `Invalid plaintext length in header: too large for ChaCha20` | `plain_len > 256 GiB` |
| `File size mismatch: header expects N bytes, file has M` | 文件长度与头部不符（截断 / 追加 / 篡改） |
| `Output file would overwrite the input file: <path>` | 输出名撞上输入名 |
| `File already exists: <path>` | 目标已存在（含落位瞬间被别人抢先创建） |
| `Wrong password or corrupted file` | HMAC 不匹配：密码错，或头部/密文被篡改 |
| `Failed to flush file to disk` / `Failed to move temporary file into place` | 落盘或改名失败（磁盘满、权限、跨卷等） |

所有错误由 CLI 打成一行 ` Error: ...`，退出码 1。

## 9. 失败时的不变量

| 场景 | 磁盘状态 |
|---|---|
| magic / 头部 / 长度校验失败 | 目标不存在，无临时文件 |
| 密码错（小文件） | 目标不存在，无临时文件，**明文从未落盘** |
| 密码错（大文件） | 目标不存在，临时文件被删除 |
| 密文被篡改（改中间字节） | 同"密码错" |
| 密文被截断 1 字节 | `File size mismatch`，目标不存在 |
| 目标已存在 | 原文件字节不变 |
| 落位时目标被别的进程抢先创建 | `File already exists`，临时文件被删除 |
| 进程被强杀 / 断电（大文件） | 可能残留 `<目标>.tmp-<hex>`；**目标路径**不出现半成品 |

**输入密文永远只读。**

## 10. 性能

- **只读一遍密文**：旧实现是"先整文件验 MAC，再 seek 回去解密"，大文件 IO 翻倍；现在边读边解边算 MAC，一次读完。
- 输出同样是"临时文件 + fsync + 原子改名"，不会因为加速而牺牲安全性。
- 小文件路径多一次整块内存拷贝（解密前），但省掉了"验证前先落盘"的风险。
- 实际速度由磁盘决定（同盘读 + 写），密码学部分约 1.7 GiB/s；见 [加密流程 §10](encryption.md#10-性能)。

## 11. 步骤速查

```
1  打开输入，读 42 字节固定头 → 校验 magic、iterations → salt、nonce
2  读 ext_len + extension → 净化 → 读 plain_len
3  validate_layout：plain_len ≤ 256 GiB 且 header.size + plain_len + 32 == 文件大小
4  还原输出名（去 .bs9p → 按需补扩展名 → 应用 -o）
5  检查输出 ≠ 输入、输出不存在
6  master = PBKDF2(password, salt, iterations)
   stream/mac/dict = HMAC-SHA256(master, "bs9p/{stream,mac,dict}")
7  DataDict ← ChaCha20(dict, 0^12, 0)；mac.update(header.raw)
8  小文件：读全部密文进内存并算 MAC → 比对 tag → 解密 → 一次性写入临时文件 → commit
   大文件：边读边算 MAC 边解密写入临时文件 → 比对 tag → commit（失败则删临时文件）
9  输出 " Decode successfully: <path>"
```

## 12. 相关代码

| 步骤 | 位置 |
|---|---|
| CLI 参数、密码读取、进度条开关 | [`src/main.cpp`](../src/main.cpp) |
| 头部解析、布局校验、两条解密路径 | [`include/core.hpp`](../include/core.hpp) `read_header()` / `validate_layout()` / `decode_file()` |
| 密钥派生 | [`include/key.hpp`](../include/key.hpp) `derive_keys()` |
| 置换表反查 | [`include/data_dict.hpp`](../include/data_dict.hpp) `decode()` |
| ChaCha20 | [`include/chacha20.hpp`](../include/chacha20.hpp) |
| HMAC 与常量时间比较 | [`include/sha256.hpp`](../include/sha256.hpp) / [`include/key.hpp`](../include/key.hpp) |
| 原子落位与清理 | [`include/atomic_file.hpp`](../include/atomic_file.hpp) |
| 进度条 | [`include/progress.hpp`](../include/progress.hpp) |
