# KryptosCore — Internal Architecture & Algorithms

This document describes the internal algorithms and data flow in detail, intended for developers porting KryptosCore to other programming languages. Any conforming implementation that follows these specifications will produce **identical output** for the same inputs.

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Deterministic Random Stream](#2-deterministic-random-stream)
- [3. Uniform Random Selection](#3-uniform-random-selection)
- [4. Password Generation Algorithm](#4-password-generation-algorithm)
- [5. Seed Construction](#5-seed-construction)
- [6. Cryptographic Primitives](#6-cryptographic-primitives)
  - [6.1 HMAC-SHA256](#61-hmac-sha256)
  - [6.2 PBKDF2-HMAC-SHA256](#62-pbkdf2-hmac-sha256)
  - [6.3 Authenticated Encryption](#63-authenticated-encryption)
- [7. Serialisation Format](#7-serialisation-format)
- [8. Base64 Encoding](#8-base64-encoding)
- [9. Character Sets](#9-character-sets)
- [10. Porting Checklist](#10-porting-checklist)

---

## 1. Overview

KryptosCore is a **deterministic password generator**. Given the same inputs — prefix (passphrase), website name, UUID, username, password length, and character set — it always produces the same password. No password is ever stored.

Data flow:

```
prefix ──► SHA256(prefix)──┐
                           ├──► concatenate with \x00 delimiters ──► SHA256 ──► seed (hex)
webname, uuid, username ───┘                                                       │
                                                                                   ▼
                                                              DeterministicStream(seed)
                                                                       │
                                                                       ▼
                                                              GeneratePassword(seed, L, charsets)
                                                                       │
                                                                       ▼
                                                                   password
```

---

## 2. Deterministic Random Stream

The stream produces an infinite sequence of pseudo-random bytes from a seed string.

### Initialisation

```
internal_seed = SHA256_raw(seed_string)    // 32 bytes
counter = 0                                // 64-bit unsigned integer
buffer = []                                // empty byte buffer
pos = 0
Refill()                                   // generate first block
```

### Refill

```
input = internal_seed || big_endian_64(counter)    // 32 + 8 = 40 bytes
buffer = SHA256_raw(input)                         // 32 bytes
counter += 1
pos = 0
```

### NextByte

```
if pos >= len(buffer):
    Refill()
byte = buffer[pos]
pos += 1
return byte
```

### NextUint32

Read 4 bytes in **big-endian** order:

```
result = (NextByte() << 24) | (NextByte() << 16) | (NextByte() << 8) | NextByte()
```

**Critical:** The byte order is big-endian. This must match across all implementations.

---

## 3. Uniform Random Selection

`UniformRandom(n)` returns a value in `[0, n)` with **zero modulo bias**.

### Algorithm (Rejection Sampling)

```
full_range = 2^32                         // 4294967296
limit = (full_range / n) * n              // largest multiple of n ≤ 2^32

loop:
    r = NextUint32()
    if r < limit:
        return r % n
    // else: reject and retry
```

**Important:** The division `full_range / n` is integer division. `limit` is computed as `(full_range // n) * n` using 64-bit arithmetic to avoid overflow.

---

## 4. Password Generation Algorithm

```
function GeneratePassword(seed: string, length: int, charsets: list[string]) -> string:

    assert len(charsets) > 0
    assert length >= len(charsets)
    assert all(len(cs) > 0 for cs in charsets)

    stream = DeterministicStream(seed)
    num_sets = len(charsets)
    result = array of length chars (uninitialised)
    used = array of num_sets booleans, all false
    used_count = 0

    // Phase 1: Assign each position to a charset
    for i in 0 .. length-1:
        remaining = length - i
        unrepresented = num_sets - used_count

        loop:                                         // retry until unique maximum
            weights = [stream.NextUint32() for j in 0..num_sets-1]

            if unrepresented == remaining:            // forced coverage
                for j in 0..num_sets-1:
                    if used[j]:
                        weights[j] = 0

            max_val = max(weights)
            max_indices = [j for j in 0..num_sets-1 if weights[j] == max_val]

            if len(max_indices) == 1:
                chosen = max_indices[0]
                break
            // else: tie → regenerate weights (extremely rare for uint32)

        // Phase 2: Pick a character uniformly from the chosen charset
        char_idx = stream.UniformRandom(len(charsets[chosen]))
        result[i] = charsets[chosen][char_idx]

        if not used[chosen]:
            used[chosen] = true
            used_count += 1

    // Phase 3: Fisher-Yates shuffle (eliminates positional bias)
    for i in (length-1) downto 1:
        j = stream.UniformRandom(i + 1)
        swap(result[i], result[j])

    return result as string
```

### Key Points for Portability

1. The **retry loop** for tie-breaking consumes random stream bytes. Ties are extremely unlikely (two `uint32` values colliding), but the logic must be identical.
2. The **coverage constraint** only activates when `unrepresented == remaining` — i.e., every remaining position must go to a not-yet-used charset.
3. `UniformRandom` for character selection happens **after** charset selection, consuming additional stream bytes.
4. The **Fisher-Yates shuffle** runs from index `length-1` down to `1`, using `UniformRandom(i+1)` for each position.

---

## 5. Seed Construction

```
function ConstructSeed(prefix, webname, uuid, username) -> string:
    prefix_hash = SHA256_raw(prefix)                // 32 bytes (raw binary)

    material = prefix_hash
             + b"\x00"
             + encode_utf8(webname)
             + b"\x00"
             + encode_utf8(uuid)
             + b"\x00"
             + encode_utf8(username)

    return SHA256_hex(material)                     // 64-char hex string
```

**Why null-byte delimiters:** Prevents ambiguity. Without them, `("ab", "cd")` and `("abc", "d")` would produce the same concatenation.

**Why hash prefix separately:** The prefix is the user's secret. By hashing it before concatenation, it cannot be recovered even if all other fields are known.

---

## 6. Cryptographic Primitives

### 6.1 HMAC-SHA256

Standard RFC 2104 construction:

```
function HmacSha256(key: bytes, message: bytes) -> bytes:
    block_size = 64

    if len(key) > block_size:
        key = SHA256_raw(key)
    key = key padded with 0x00 to block_size bytes

    ipad_key = key XOR (block_size bytes of 0x36)
    opad_key = key XOR (block_size bytes of 0x5C)

    inner = SHA256_raw(ipad_key + message)
    return SHA256_raw(opad_key + inner)             // 32 bytes
```

### 6.2 PBKDF2-HMAC-SHA256

Single-block derivation (produces 32 bytes):

```
function DeriveKey(password, salt, iterations=100000) -> bytes:
    // Block 1: U_1 = HMAC(password, salt || 0x00000001)
    salt_block = salt + b"\x00\x00\x00\x01"        // big-endian 32-bit block index
    U = HMAC_SHA256(password, salt_block)
    derived = U                                     // copy

    for i in 1 .. iterations-1:
        U = HMAC_SHA256(password, U)
        derived = derived XOR U                     // byte-wise XOR

    return derived                                  // 32 bytes
```

### 6.3 Authenticated Encryption

**Encrypt:**

```
function Encrypt(plaintext, key, nonce) -> bytes:
    if key is empty:
        return plaintext

    derived = DeriveKey(key, nonce, 100000)          // 32-byte encryption key
    stream = DeterministicStream(derived)

    ciphertext = plaintext XOR stream bytes          // byte-by-byte

    tag = HMAC_SHA256(derived, nonce + ciphertext)   // 32 bytes

    return nonce + ciphertext + tag                  // 16 + len(plaintext) + 32
```

**Decrypt:**

```
function Decrypt(data, key) -> bytes:
    if key is empty:
        return data

    nonce = data[0:16]
    ciphertext = data[16 : len(data)-32]
    tag = data[len(data)-32 :]

    derived = DeriveKey(key, nonce, 100000)

    expected_tag = HMAC_SHA256(derived, nonce + ciphertext)

    // Constant-time comparison
    diff = 0
    for i in 0..31:
        diff |= tag[i] XOR expected_tag[i]
    if diff != 0:
        error("authentication failed")

    stream = DeterministicStream(derived)
    plaintext = ciphertext XOR stream bytes

    return plaintext
```

**Nonce:** 16 bytes of cryptographically random data. Must be unique per encryption but does not need to be secret.

---

## 7. Serialisation Format

### Text Format (local storage)

```
KRYPTOS:V1\n
<entry_count>\n
<webname>\t<uuid>\t<username>\t<length>\t<charset_preset>\n
<webname>\t<uuid>\t<username>\t<length>\t<charset_preset>\n
...
```

- Line separator: `\n` (LF, 0x0A).
- Field separator: `\t` (TAB, 0x09).
- Fields are escaped: `\` → `\\`, TAB → `\t`, LF → `\n`, CR → `\r`.
- `length` is a decimal integer.
- `charset_preset` is a string: `"full"` or `"alphanum"`.

### Base64 Export

1. Serialise to text format (above).
2. Optionally encrypt with `Encrypt(text, key, nonce)`.
3. Encode the result with RFC 4648 Base64.

Import is the reverse.

---

## 8. Base64 Encoding

Standard RFC 4648 alphabet:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

Padding character: `=`.

Encoding processes 3 input bytes → 4 output characters. Padding is applied at the end.

---

## 9. Character Sets

The exact character set definitions are critical for cross-language consistency.

| Preset Name | Sets | Exact Strings |
|---|---|---|
| `"full"` | 4 | `["abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789", "!@#$%^&*()-_=+[]{}\|;:,.<>?/~"]` |
| `"alphanum"` | 3 | `["abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789"]` |

**Order matters.** The charsets are always provided in this exact order (lowercase, uppercase, digits, [symbols]). The weight-vector indices correspond to this order.

Symbols set (28 characters, in order):

```
! @ # $ % ^ & * ( ) - _ = + [ ] { } | ; : , . < > ? / ~
```

---

## 10. Porting Checklist

When implementing KryptosCore in another language, verify each of these produces identical output:

- [ ] **SHA-256** — use a well-tested library. Verify against test vectors.
- [ ] **DeterministicStream** — verify `NextByte()`, `NextUint32()` output for a known seed.
- [ ] **UniformRandom(n)** — verify rejection sampling produces the same sequence.
- [ ] **GeneratePassword** — test with known seed, length, and charsets. Compare output character-by-character.
- [ ] **ConstructSeed** — verify the double-hash + null-delimiter concatenation.
- [ ] **HMAC-SHA256** — verify against RFC 4231 test vectors.
- [ ] **PBKDF2** — verify against RFC 6070 test vectors.
- [ ] **Encrypt/Decrypt** — round-trip test with known key and nonce.
- [ ] **Base64** — verify against RFC 4648 test vectors.
- [ ] **Serialisation** — test escape/unescape with special characters.
- [ ] **Character sets** — character order and content must exactly match.

### Recommended Test Vector

```
Seed:     "test_seed"
Length:   16
Charsets: Full() (4 sets)
```

Generate the password and compare with the C++ reference implementation. If it matches, all stream/selection/shuffle logic is correct.
