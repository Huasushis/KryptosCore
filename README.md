# KryptosCore

A deterministic, zero-knowledge password manager.  
Passwords are never stored — they are regenerated on-the-fly from a master prefix (passphrase) and per-entry metadata using SHA-256.

> Built with **Claude Opus 4.6**

[中文](#中文) | [English](#english)

---

<a id="english"></a>

## Features

- **Zero-knowledge** — only metadata (site name, username, UUID) is persisted; passwords exist only in memory during generation.
- **Deterministic** — the same inputs always produce the same password, across platforms and languages.
- **Prefix isolation** — the user-supplied prefix is SHA-256 hashed before it enters the seed chain, so it can never be recovered from stored data.
- **Guaranteed charset coverage** — every required character class (lowercase, uppercase, digits, symbols) appears at least once, enforced by a weight-vector algorithm with Fisher-Yates post-shuffle to eliminate positional bias.
- **Uniform randomness** — character selection uses rejection sampling on `uint32` values, removing modulo bias entirely.
- **Authenticated encryption** — export data can be encrypted with PBKDF2-HMAC-SHA256 key derivation (100 000 iterations), XOR stream cipher, and HMAC-SHA256 authentication tag.
- **Secure memory** — sensitive strings (prefix, password) are overwritten with volatile writes before deallocation.
- **Cross-platform clipboard** — passwords are automatically copied to the clipboard (Win32 API / pbcopy / xclip).
- **Portable data file** — the data file lives next to the executable, so you can put it on a USB drive or add it to `PATH`.

## Quick Start

### Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The executable `kryptos` (or `kryptos.exe` on Windows) is produced in the `build/` directory.

### Usage

```
kryptos                          # Interactive menu
kryptos <webname>                # Generate password (single account)
kryptos <webname> <username>     # Generate password (specific account)
kryptos add                      # Add a new entry
kryptos list                     # List all entries
kryptos delete <web> [user]      # Delete an entry
kryptos export [file]            # Export data as Base64
kryptos import <file>            # Import data from Base64
kryptos help                     # Show help
```

When generating a password you are prompted for a **prefix** via silent input (characters are not echoed).  The prefix defaults to empty if you just press Enter.

### Examples

```bash
# Add a new entry interactively
kryptos add

# Generate password for github.com (only one account stored)
kryptos github.com

# Multiple accounts — specify the username
kryptos github.com user@example.com

# Export all entries (encrypted)
kryptos export backup.txt

# Import entries (merge)
kryptos import backup.txt
```

## Architecture

```
KryptosCore/
├── include/kryptos/
│   ├── core.h            # DeterministicStream, GeneratePassword, ConstructSeed
│   ├── crypto_utils.h    # Base64, HMAC-SHA256, PBKDF2, Encrypt/Decrypt
│   └── manager.h         # AccountManager, AccountEntry, serialisation
├── src/
│   ├── core.cpp
│   ├── crypto_utils.cpp
│   └── manager.cpp
├── example/
│   └── main.cpp          # Cross-platform CLI application
├── docs/
│   ├── API.md            # Public API reference
│   └── ARCHITECTURE.md   # Internal algorithms (for porting)
├── .github/workflows/
│   └── release.yml       # Auto-build & release on push
├── CMakeLists.txt        # FetchContent pulls picosha2 automatically
└── .gitignore
```

### Documentation

- [**API Reference**](docs/API.md) — public interface for library consumers.
- [**Architecture & Algorithms**](docs/ARCHITECTURE.md) — internal implementation details for porting to other languages.

### Core module (`core.h / core.cpp`)

| Component | Description |
|---|---|
| `DeterministicStream` | SHA-256-based CSPRNG: hashes `seed \|\| counter` in 32-byte blocks. |
| `UniformRandom(n)` | Rejection sampling over `uint32` — zero modulo bias. |
| `GeneratePassword` | Weight-vector charset selection with coverage guarantee + Fisher-Yates shuffle. |
| `ConstructSeed` | `SHA256(SHA256(prefix) \|\| 0x00 \|\| webname \|\| 0x00 \|\| uuid \|\| 0x00 \|\| username)` |

### Crypto utilities (`crypto_utils.h / crypto_utils.cpp`)

| Component | Description |
|---|---|
| `Base64Encode / Decode` | RFC 4648 Base64 codec. |
| `HmacSha256` | Standard HMAC-SHA256 (RFC 2104). |
| `DeriveKey` | PBKDF2-HMAC-SHA256 with configurable iteration count. |
| `Encrypt / Decrypt` | `nonce(16B) \|\| XOR-ciphertext \|\| HMAC-tag(32B)`. Constant-time tag verification. |
| `SecureClear` | Volatile memory wipe to prevent optimiser elision. |

### Manager module (`manager.h / manager.cpp`)

- Pure data operations — **no file I/O or system calls**.
- Stores entries as `(webname, uuid, username, length, charset_preset)`.
- Text serialisation: tab-separated, escaped, one entry per line (`KRYPTOS:V1` header).
- `ExportBase64` / `ImportBase64` with optional authenticated encryption.
- Supports merge-import to combine data from multiple devices.

### CLI example (`example/main.cpp`)

- Interactive menu **and** one-liner command-line interface.
- Data file stored alongside the executable (works from `PATH`).
- Silent prefix input (no echo).
- Cross-platform clipboard copy (Win32 / pbcopy / xclip).
- UUID generated from `std::random_device` and hidden from the user.

## Security Design

1. **Prefix never stored** — hashed before entering the seed chain.
2. **UUID as salt** — a 128-bit random value per entry prevents rainbow-table attacks even if the prefix is weak.
3. **PBKDF2 for export encryption** — 100 000 rounds of HMAC-SHA256 slow down brute-force attempts on the export key.
4. **Encrypt-then-MAC** — ciphertext authenticity is verified before decryption; constant-time comparison prevents timing side-channels.
5. **Volatile memory wipe** — sensitive strings are zeroed before `std::string::clear()`.

## Dependencies

- **C++17** (for `<filesystem>`)
- **picosha2** (header-only SHA-256, MIT license, fetched automatically via CMake FetchContent)
- No other external libraries.

## License

MIT — see [LICENSE](LICENSE) for details.

---

<a id="中文"></a>

# KryptosCore（中文）

一个确定性的零知识密码管理器。  
密码从不存储——它们通过主前缀（口令）与条目元数据，基于 SHA-256 实时生成。

> 使用 **Claude Opus 4.6** 构建

## 特性

- **零知识** — 仅持久化元数据（站点名、用户名、UUID），密码只在生成时存在于内存中。
- **确定性** — 相同输入始终生成相同密码，跨平台、跨语言一致。
- **前缀隔离** — 用户提供的前缀在进入种子链前先经 SHA-256 哈希，无法从存储数据中还原。
- **字符集全覆盖** — 权重向量算法保证每类字符（小写、大写、数字、符号）至少出现一次，Fisher-Yates 洗牌消除位置偏差。
- **均匀随机** — 字符选择使用 `uint32` 拒绝采样，完全消除取模偏差。
- **认证加密** — 导出数据支持 PBKDF2-HMAC-SHA256 密钥派生（100,000 轮）+ XOR 流密码 + HMAC-SHA256 认证标签。
- **安全内存** — 敏感字符串（前缀、密码）在释放前使用 volatile 写入覆零。
- **跨平台剪贴板** — 自动复制密码到剪贴板（Win32 API / pbcopy / xclip）。
- **便携数据文件** — 数据文件与可执行文件同目录，可放在 U 盘或添加到 `PATH` 使用。

## 快速开始

### 构建

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

生成的可执行文件 `kryptos`（Windows 下为 `kryptos.exe`）位于 `build/` 目录。

### 用法

```
kryptos                          # 交互式菜单
kryptos <站点名>                  # 生成密码（单账号）
kryptos <站点名> <用户名>         # 生成密码（指定账号）
kryptos add                      # 添加新条目
kryptos list                     # 列出所有条目
kryptos delete <站点> [用户名]    # 删除条目
kryptos export [文件]             # 导出为 Base64
kryptos import <文件>             # 从 Base64 导入
kryptos help                     # 显示帮助
```

生成密码时会提示输入 **前缀**（静默输入，字符不回显）。直接按回车则前缀为空。

### 示例

```bash
# 交互式添加新条目
kryptos add

# 为 github.com 生成密码（仅存储一个账号时）
kryptos github.com

# 多账号 — 指定用户名
kryptos github.com user@example.com

# 导出所有条目（加密）
kryptos export backup.txt

# 导入条目（合并）
kryptos import backup.txt
```

## 架构

```
KryptosCore/
├── include/kryptos/
│   ├── core.h            # 确定性随机流、密码生成、种子构造
│   ├── crypto_utils.h    # Base64、HMAC-SHA256、PBKDF2、加解密
│   └── manager.h         # 账号管理、条目、序列化
├── src/
│   ├── core.cpp
│   ├── crypto_utils.cpp
│   └── manager.cpp
├── example/
│   └── main.cpp          # 跨平台控制台应用
├── docs/
│   ├── API.md            # 公开 API 参考
│   └── ARCHITECTURE.md   # 内部算法（便于移植）
├── .github/workflows/
│   └── release.yml       # 推送时自动构建与发布
├── CMakeLists.txt        # FetchContent 自动拉取 picosha2
└── .gitignore
```

### 文档

- [**API 参考**](docs/API.md) — 面向库使用者的公开接口文档。
- [**架构与算法**](docs/ARCHITECTURE.md) — 面向其他语言移植的内部实现细节。

### 核心模块（`core.h / core.cpp`）

| 组件 | 说明 |
|---|---|
| `DeterministicStream` | 基于 SHA-256 的伪随机流：对 `seed \|\| counter` 哈希，每次产出 32 字节。 |
| `UniformRandom(n)` | `uint32` 拒绝采样——零取模偏差。 |
| `GeneratePassword` | 权重向量字符集选择 + 覆盖保证 + Fisher-Yates 洗牌。 |
| `ConstructSeed` | `SHA256(SHA256(prefix) \|\| 0x00 \|\| webname \|\| 0x00 \|\| uuid \|\| 0x00 \|\| username)` |

### 密码工具（`crypto_utils.h / crypto_utils.cpp`）

| 组件 | 说明 |
|---|---|
| `Base64Encode / Decode` | RFC 4648 Base64 编解码。 |
| `HmacSha256` | 标准 HMAC-SHA256（RFC 2104）。 |
| `DeriveKey` | PBKDF2-HMAC-SHA256，可配置迭代次数。 |
| `Encrypt / Decrypt` | `nonce(16B) \|\| XOR密文 \|\| HMAC标签(32B)`。常量时间标签验证。 |
| `SecureClear` | volatile 内存擦除，防止编译器优化消除。 |

### 管理模块（`manager.h / manager.cpp`）

- 纯数据操作——**无文件 I/O 或系统调用**。
- 条目格式：`(站点名, uuid, 用户名, 密码长度, 字符集预设)`。
- 文本序列化：Tab 分隔、转义，每行一条（`KRYPTOS:V1` 头部）。
- `ExportBase64` / `ImportBase64` 支持可选的认证加密。
- 支持合并导入，方便多设备间同步。

### 控制台示例（`example/main.cpp`）

- 交互式菜单 **与** 一行命令行接口。
- 数据文件与可执行文件同目录（支持从 `PATH` 运行）。
- 静默前缀输入（无回显）。
- 跨平台剪贴板复制（Win32 / pbcopy / xclip）。
- UUID 由 `std::random_device` 生成，对用户隐藏。

## 安全设计

1. **前缀从不存储** — 进入种子链前先哈希。
2. **UUID 作为盐** — 每条目 128 位随机值，即使前缀较弱也能防止彩虹表攻击。
3. **PBKDF2 用于导出加密** — 100,000 轮 HMAC-SHA256 减缓暴力破解。
4. **Encrypt-then-MAC** — 先加密后认证，解密前验证完整性；常量时间比较防止时序侧信道。
5. **volatile 内存擦除** — 敏感字符串在 `std::string::clear()` 前置零。

## 依赖

- **C++17**（使用 `<filesystem>`）
- **picosha2**（纯头文件 SHA-256，MIT 协议，通过 CMake FetchContent 自动获取）
- 无其他外部依赖。

## 许可证

MIT — 详见 [LICENSE](LICENSE)。