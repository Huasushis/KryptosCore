# KryptosCore API Reference

This document describes the public C++ API of KryptosCore.  
All symbols live in the `kryptos` namespace. Include paths assume `include/` is on the compiler search path.

---

## Table of Contents

- [Core (`kryptos/core.h`)](#core)
  - [DeterministicStream](#deterministicstream)
  - [Charset Presets](#charset-presets)
  - [GeneratePassword](#generatepassword)
  - [ConstructSeed](#constructseed)
  - [Sha256Hex / Sha256Raw](#sha256)
- [Crypto Utilities (`kryptos/crypto_utils.h`)](#crypto-utilities)
  - [Base64Encode / Base64Decode](#base64)
  - [HmacSha256](#hmacsha256)
  - [DeriveKey](#derivekey)
  - [Encrypt / Decrypt](#encrypt--decrypt)
  - [SecureClear](#secureclear)
- [Manager (`kryptos/manager.h`)](#manager)
  - [AccountEntry](#accountentry)
  - [AccountManager](#accountmanager)

---

<a id="core"></a>

## Core — `#include "kryptos/core.h"`

<a id="deterministicstream"></a>

### `class DeterministicStream`

A deterministic pseudo-random byte stream seeded by a string.

```cpp
explicit DeterministicStream(const std::string& seed);
```

| Method | Signature | Description |
|---|---|---|
| `NextByte` | `uint8_t NextByte()` | Returns the next pseudo-random byte from the stream. |
| `NextUint32` | `uint32_t NextUint32()` | Returns the next 4 bytes assembled as a big-endian `uint32_t`. |
| `UniformRandom` | `size_t UniformRandom(size_t n)` | Returns a uniformly distributed index in `[0, n)`. Uses rejection sampling — zero modulo bias. |

**Thread safety:** Not thread-safe. Each thread should use its own instance.

---

<a id="charset-presets"></a>

### Charset Presets — `kryptos::charset`

#### Constants

| Constant | Value |
|---|---|
| `kLowercase` | `"abcdefghijklmnopqrstuvwxyz"` |
| `kUppercase` | `"ABCDEFGHIJKLMNOPQRSTUVWXYZ"` |
| `kDigits` | `"0123456789"` |
| `kSymbols` | `"!@#$%^&*()-_=+[]{}\|;:,.<>?/~"` |

#### Functions

| Function | Signature | Description |
|---|---|---|
| `Full` | `vector<string> Full()` | Returns `{kLowercase, kUppercase, kDigits, kSymbols}`. |
| `AlphaNumeric` | `vector<string> AlphaNumeric()` | Returns `{kLowercase, kUppercase, kDigits}`. |
| `AlphaNumericSymbol` | `vector<string> AlphaNumericSymbol()` | Same as `Full()`. |
| `FromPresetName` | `vector<string> FromPresetName(const string& name)` | Lookup by name: `"alphanum"` → `AlphaNumeric()`, otherwise `Full()`. |
| `ToPresetName` | `string ToPresetName(const vector<string>& charsets)` | Best-effort reverse lookup. Returns `"alphanum"` or `"full"`. |

---

<a id="generatepassword"></a>

### `GeneratePassword`

```cpp
std::string GeneratePassword(
    const std::string& seed,
    int length,
    const std::vector<std::string>& charsets);
```

Generate a deterministic password.

| Parameter | Description |
|---|---|
| `seed` | Seed string (typically from `ConstructSeed`). |
| `length` | Desired password length. Must be ≥ `charsets.size()`. |
| `charsets` | Character classes. Each must be non-empty. Every class is guaranteed to appear at least once. |

**Returns:** A `std::string` of exactly `length` characters.

**Throws:** `std::invalid_argument` if `charsets` is empty, any charset is empty, or `length < charsets.size()`.

---

<a id="constructseed"></a>

### `ConstructSeed`

```cpp
std::string ConstructSeed(
    const std::string& prefix,
    const std::string& webname,
    const std::string& uuid,
    const std::string& username);
```

Build the seed for `GeneratePassword` from account metadata.

| Parameter | Description |
|---|---|
| `prefix` | User's secret passphrase. Hashed independently — never stored. Can be empty. |
| `webname` | Website or app name. |
| `uuid` | Per-entry random identifier (created once, stored). |
| `username` | Account identifier (email, phone, etc.). |

**Returns:** A 64-character hex string: `SHA256(SHA256(prefix) || \x00 || webname || \x00 || uuid || \x00 || username)`.

---

<a id="sha256"></a>

### `Sha256Hex` / `Sha256Raw`

```cpp
std::string Sha256Hex(const std::string& input);   // 64-char hex string
std::string Sha256Raw(const std::string& input);    // 32-byte raw digest
```

---

<a id="crypto-utilities"></a>

## Crypto Utilities — `#include "kryptos/crypto_utils.h"`

All symbols are in `kryptos::crypto`.

<a id="base64"></a>

### `Base64Encode` / `Base64Decode`

```cpp
std::string Base64Encode(const std::string& input);
std::string Base64Decode(const std::string& input);
```

Standard RFC 4648 Base64. `Base64Decode` returns an empty string on invalid input.

---

<a id="hmacsha256"></a>

### `HmacSha256`

```cpp
std::string HmacSha256(const std::string& key, const std::string& message);
```

Compute HMAC-SHA256 per RFC 2104. Returns raw 32-byte digest.

---

<a id="derivekey"></a>

### `DeriveKey`

```cpp
std::string DeriveKey(
    const std::string& password,
    const std::string& salt,
    int iterations = 100000);
```

PBKDF2-HMAC-SHA256 (single 32-byte block). Returns a 32-byte derived key.

---

<a id="encrypt--decrypt"></a>

### `Encrypt` / `Decrypt`

```cpp
std::string Encrypt(const std::string& plaintext,
                    const std::string& key,
                    const std::string& nonce);

std::string Decrypt(const std::string& ciphertext,
                    const std::string& key);
```

Authenticated encryption using encrypt-then-MAC.

**Wire format:** `nonce (16 bytes) || ciphertext || HMAC-SHA256 tag (32 bytes)`

| Behaviour | When `key` is empty |
|---|---|
| `Encrypt` | Returns `plaintext` as-is. |
| `Decrypt` | Returns `ciphertext` as-is. |

**Throws:** `std::runtime_error` on authentication failure (wrong key or corrupted data).

---

<a id="secureclear"></a>

### `SecureClear`

```cpp
void SecureClear(std::string& s);
```

Overwrites `s` with zeros using volatile writes (prevents compiler optimisation), then clears the string.

---

<a id="manager"></a>

## Manager — `#include "kryptos/manager.h"`

<a id="accountentry"></a>

### `struct AccountEntry`

```cpp
struct AccountEntry {
    std::string webname;
    std::string uuid;
    std::string username;
    int         length = 16;
    std::string charset_preset = "full";

    std::string GeneratePassword(const std::string& prefix) const;
};
```

| Field | Description |
|---|---|
| `webname` | Website or application name. |
| `uuid` | Random unique ID, generated once at creation time. |
| `username` | User-visible identifier (email, phone, etc.). |
| `length` | Password length (default 16). |
| `charset_preset` | `"full"` or `"alphanum"`. |

`GeneratePassword(prefix)` calls `ConstructSeed` and `kryptos::GeneratePassword` internally.

---

<a id="accountmanager"></a>

### `class AccountManager`

Pure data management — **no file I/O or system calls**.

#### Entry Management

| Method | Signature | Description |
|---|---|---|
| `AddEntry` | `bool AddEntry(webname, uuid, username, length=16, charset_preset="full")` | Add a new entry. Returns `false` if `(webname, username)` already exists. UUID must be provided by the caller (use CSPRNG). |
| `RemoveEntry` | `bool RemoveEntry(webname, username)` | Remove by webname + username. Returns `true` if found. |
| `FindByWebname` | `vector<const AccountEntry*> FindByWebname(webname)` | Find all entries for a given site. |
| `FindEntry` | `const AccountEntry* FindEntry(webname, username)` | Find a specific entry. Returns `nullptr` if not found. |
| `Entries` | `const vector<AccountEntry>& Entries()` | Read-only access to all entries. |
| `Size` | `size_t Size()` | Number of entries. |

#### Serialisation (Text)

```cpp
std::string SerializeToText() const;
bool DeserializeFromText(const std::string& text);
```

Format:

```
KRYPTOS:V1
<entry_count>
<webname>\t<uuid>\t<username>\t<length>\t<charset_preset>
...
```

Fields are escaped (`\t` → `\\t`, `\n` → `\\n`, `\\` → `\\\\`).

#### Export / Import (Base64)

```cpp
std::string ExportBase64(const std::string& key = "",
                         const std::string& nonce = "") const;

void ImportBase64(const std::string& base64,
                  const std::string& key = "",
                  bool merge = false);
```

| Parameter | Description |
|---|---|
| `key` | Encryption/decryption key. Empty = no encryption. |
| `nonce` | 16 random bytes (required when `key` is non-empty). |
| `merge` | If `true`, append entries (skip duplicates). If `false`, replace all. |

**Throws:** `std::runtime_error` on decryption failure or parse error.

---

## Quick Usage Example

```cpp
#include "kryptos/core.h"
#include "kryptos/manager.h"

int main() {
    kryptos::AccountManager mgr;

    // Add an entry (UUID should come from a CSPRNG in production).
    mgr.AddEntry("github.com", "a1b2c3d4e5f6...", "user@example.com");

    // Generate password.
    auto* entry = mgr.FindEntry("github.com", "user@example.com");
    std::string password = entry->GeneratePassword("my_secret_prefix");

    // Serialise for storage.
    std::string data = mgr.SerializeToText();

    // Export encrypted Base64 for transfer.
    std::string nonce(16, '\0');  // Use real random bytes!
    std::string exported = mgr.ExportBase64("transfer_key", nonce);

    return 0;
}
```
