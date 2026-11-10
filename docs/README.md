# bs9p 文档

这里放**格式与算法**的参考文档；`README.md`（仓库根）是使用手册。两边互相链接：

- 想直接上手：看 [根 README](../README.md)
- 想弄清密文里每个字节、或自己实现解析/加密：继续往下读

## 文档地图

| 文档 | 内容 | 适合谁 |
|---|---|---|
| [文件数据结构](file-format.md) | 密文的二进制布局：字段、偏移、字节序、长度公式、约束、真实 hexdump 示例、解析伪代码 | 要自己解析或生成 `.bs9p` 的人 |
| [加密流程](encryption.md) | `encode` 的完整执行顺序：前置检查、头部构造、密钥派生、置换表生成、主循环顺序、标签、原子落位、失败不变量 | 想确认"到底做了什么"、或要复刻实现的人 |
| [解密流程](decryption.md) | `decode` 的完整执行顺序：头部校验、布局校验、输出名还原、两条解密路径、错误对照、失败不变量 | 排查"为什么解不开"、或要复刻实现的人 |

## 建议阅读顺序

1. **[文件数据结构](file-format.md)** —— 先建立"密文长什么样"的直觉：`header ‖ ciphertext ‖ tag`，总长 `plain_len + ext_len + 82`
2. **[加密流程](encryption.md)** —— 看每个字段是怎么算出来的：密钥派生 → 置换表 → 逐块 `查表 → XOR → HMAC`
3. **[解密流程](decryption.md)** —— 看这些字段是怎么被反向消费的，以及为什么校验顺序必须是这样

三篇里的字段名、常量、错误信息都与代码保持一致；引用位置用 `文件:行` 或函数名标注。

## 与其他文档的关系

| 你想知道 | 去哪看 |
|---|---|
| 怎么装、怎么构建、怎么用 | [根 README](../README.md) |
| 命令行参数、密码的三种给法、进度条 | [根 README](../README.md) 的「使用」与「命令行参数」 |
| 密文的字节级布局 | [文件数据结构](file-format.md) |
| 加密 / 解密每一步做了什么 | [加密流程](encryption.md) / [解密流程](decryption.md) |
| 出错信息是什么意思 | [解密流程 §8 错误对照](decryption.md#8-错误信息对照) |

## 关键常量速查

| 常量 | 值 | 位置 |
|---|---|---|
| magic | `BS9P104\0` | [`include/magic.hpp`](../include/magic.hpp) |
| salt 长度 | 16 字节 | `SALT_LEN` |
| nonce 长度 | 12 字节 | `NONCE_LEN` |
| tag 长度 | 32 字节 | `TAG_LEN` |
| PBKDF2 迭代次数 | 200000（读取端接受 1 – 10000000） | `PBKDF2_ITERATIONS` / `MAX_ITERATIONS` |
| 固定头长度 | 50 字节（不含扩展名） | `8 + 4 + 16 + 12 + 2 + 8` |
| 密文总长 | `plain_len + ext_len + 82` | 50 字节头 + 32 字节 tag |
| 扩展名上限 | 255 字节 | `MAX_EXTENSION_LEN` |
| 单文件上限 | 256 GiB（ChaCha20 计数器上限） | `chacha_max_bytes(0)` |
| 内存解密阈值 | 128 MiB | `MEMORY_DECRYPT_LIMIT` |
| 默认缓冲 | 64 KiB（可调 64 KiB – 64 MiB） | `DEFAULT_BUFFER_SIZE` / `MIN/MAX_BUFFER_SIZE` |

## 维护约定

改动格式或算法时，以下位置必须同步，否则文档会立刻过时：

1. 常量 / 字段顺序：`include/core.hpp`、`include/magic.hpp` → 更新 [文件数据结构](file-format.md) 的字段表与尺寸表
2. 每块处理顺序、校验顺序、错误信息：`include/core.hpp` → 更新 [加密流程](encryption.md) / [解密流程](decryption.md)
3. 命名规则（`+ .bs9p` / 去后缀 / 补扩展名）：`encode_file` / `decode_file` → 更新 [解密流程 §3](decryption.md#3-还原输出文件名)
4. 原子落位细节：`include/atomic_file.hpp` → 更新 [加密流程 §8](encryption.md#8-收尾标签与落位)
5. 用户可见行为（参数、默认值、进度条）：`src/main.cpp` → 同步 [根 README](../README.md)
6. 换了 magic：两处版本表（[文件数据结构 §2](file-format.md#magic)、[根 README](../README.md) 的「版本与兼容性」）都要改，并在 `tests/test_bs9p.cpp` 里补"旧 magic 必须被拒"的断言

新增字段时优先**追加在 `plain_len` 之后、密文之前**，并同步修改 `header.size` 的计算（`read_header` 用 `header.raw.size()`，`validate_layout` 用 `header.size + plain_len + TAG_LEN`）——这样旧版本会因文件大小/魔数不匹配而明确失败，而不是读出错误结果。
