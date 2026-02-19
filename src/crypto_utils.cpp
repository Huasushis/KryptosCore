// Copyright (c) 2026 Huasushis
// Licensed under the MIT License. See LICENSE file for details.

#include "kryptos/crypto_utils.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "kryptos/core.h"
#include "picosha2.h"

namespace kryptos {
namespace crypto {

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

static const char kBase64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static inline uint8_t Base64Index(char c) {
  if (c >= 'A' && c <= 'Z') return static_cast<uint8_t>(c - 'A');
  if (c >= 'a' && c <= 'z') return static_cast<uint8_t>(c - 'a' + 26);
  if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0' + 52);
  if (c == '+') return 62;
  if (c == '/') return 63;
  return 255;  // Invalid.
}

std::string Base64Encode(const std::string& input) {
  std::string output;
  output.reserve(((input.size() + 2) / 3) * 4);

  for (size_t i = 0; i < input.size(); i += 3) {
    uint32_t triple = static_cast<uint8_t>(input[i]) << 16;
    if (i + 1 < input.size()) triple |= static_cast<uint8_t>(input[i + 1]) << 8;
    if (i + 2 < input.size()) triple |= static_cast<uint8_t>(input[i + 2]);

    output.push_back(kBase64Chars[(triple >> 18) & 0x3F]);
    output.push_back(kBase64Chars[(triple >> 12) & 0x3F]);
    output.push_back((i + 1 < input.size()) ? kBase64Chars[(triple >> 6) & 0x3F]
                                             : '=');
    output.push_back((i + 2 < input.size()) ? kBase64Chars[triple & 0x3F] : '=');
  }
  return output;
}

std::string Base64Decode(const std::string& input) {
  std::string output;
  std::vector<uint8_t> buf;
  buf.reserve(4);

  for (char c : input) {
    if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
    uint8_t idx = Base64Index(c);
    if (idx == 255) return {};  // Invalid character.
    buf.push_back(idx);

    if (buf.size() == 4) {
      output.push_back(static_cast<char>((buf[0] << 2) | (buf[1] >> 4)));
      output.push_back(static_cast<char>(((buf[1] & 0x0F) << 4) | (buf[2] >> 2)));
      output.push_back(static_cast<char>(((buf[2] & 0x03) << 6) | buf[3]));
      buf.clear();
    }
  }

  // Handle remaining bytes.
  if (buf.size() >= 2) {
    output.push_back(static_cast<char>((buf[0] << 2) | (buf[1] >> 4)));
  }
  if (buf.size() >= 3) {
    output.push_back(
        static_cast<char>(((buf[1] & 0x0F) << 4) | (buf[2] >> 2)));
  }
  return output;
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

std::string HmacSha256(const std::string& key, const std::string& message) {
  static const size_t kBlockSize = 64;

  // If key is longer than block size, hash it first.
  std::string k = key;
  if (k.size() > kBlockSize) {
    k = Sha256Raw(k);
  }
  // Pad key to block size.
  k.resize(kBlockSize, '\0');

  std::string ipad_key(kBlockSize, '\0');
  std::string opad_key(kBlockSize, '\0');
  for (size_t i = 0; i < kBlockSize; ++i) {
    ipad_key[i] = static_cast<char>(k[i] ^ 0x36);
    opad_key[i] = static_cast<char>(k[i] ^ 0x5C);
  }

  // inner = SHA256(ipad_key || message)
  std::string inner_data = ipad_key + message;
  std::string inner_hash = Sha256Raw(inner_data);

  // outer = SHA256(opad_key || inner_hash)
  std::string outer_data = opad_key + inner_hash;
  return Sha256Raw(outer_data);
}

// ---------------------------------------------------------------------------
// Key derivation  (PBKDF2-HMAC-SHA256, single 32-byte block)
// ---------------------------------------------------------------------------

std::string DeriveKey(const std::string& password, const std::string& salt,
                      int iterations) {
  // PBKDF2 block 1:  U_1 = HMAC(password, salt || INT32BE(1))
  std::string salt_block = salt;
  salt_block.push_back('\x00');
  salt_block.push_back('\x00');
  salt_block.push_back('\x00');
  salt_block.push_back('\x01');

  std::string u = HmacSha256(password, salt_block);
  std::string derived = u;

  for (int i = 1; i < iterations; ++i) {
    u = HmacSha256(password, u);
    for (size_t j = 0; j < derived.size(); ++j) {
      derived[j] = static_cast<char>(derived[j] ^ u[j]);
    }
  }
  return derived;
}

// ---------------------------------------------------------------------------
// Authenticated encryption
// ---------------------------------------------------------------------------

std::string Encrypt(const std::string& plaintext, const std::string& key,
                    const std::string& nonce) {
  if (key.empty()) return plaintext;

  // Derive encryption key from (key, nonce).
  std::string derived = DeriveKey(key, nonce, 100000);

  // Generate keystream and XOR.
  DeterministicStream stream(derived);
  std::string ciphertext(plaintext.size(), '\0');
  for (size_t i = 0; i < plaintext.size(); ++i) {
    ciphertext[i] =
        static_cast<char>(static_cast<uint8_t>(plaintext[i]) ^ stream.NextByte());
  }

  // Compute HMAC over (nonce || ciphertext) for authentication.
  std::string mac_input = nonce + ciphertext;
  std::string tag = HmacSha256(derived, mac_input);

  // Output: nonce || ciphertext || tag
  return nonce + ciphertext + tag;
}

std::string Decrypt(const std::string& data, const std::string& key) {
  if (key.empty()) return data;

  static const size_t kNonceLen = 16;
  static const size_t kTagLen = 32;

  if (data.size() < kNonceLen + kTagLen) {
    throw std::runtime_error("ciphertext too short");
  }

  std::string nonce = data.substr(0, kNonceLen);
  std::string ciphertext =
      data.substr(kNonceLen, data.size() - kNonceLen - kTagLen);
  std::string tag = data.substr(data.size() - kTagLen);

  // Derive the same key.
  std::string derived = DeriveKey(key, nonce, 100000);

  // Verify HMAC.
  std::string mac_input = nonce + ciphertext;
  std::string expected_tag = HmacSha256(derived, mac_input);

  // Constant-time comparison to prevent timing attacks.
  uint8_t diff = 0;
  for (size_t i = 0; i < kTagLen; ++i) {
    diff |= static_cast<uint8_t>(tag[i] ^ expected_tag[i]);
  }
  if (diff != 0) {
    throw std::runtime_error("decryption failed: invalid key or corrupted data");
  }

  // Decrypt.
  DeterministicStream stream(derived);
  std::string plaintext(ciphertext.size(), '\0');
  for (size_t i = 0; i < ciphertext.size(); ++i) {
    plaintext[i] = static_cast<char>(static_cast<uint8_t>(ciphertext[i]) ^
                                     stream.NextByte());
  }
  return plaintext;
}

// ---------------------------------------------------------------------------
// Secure memory wipe
// ---------------------------------------------------------------------------

void SecureClear(std::string& s) {
  if (s.empty()) return;
  volatile char* p = &s[0];
  for (size_t i = 0; i < s.size(); ++i) {
    p[i] = '\0';
  }
  s.clear();
}

}  // namespace crypto
}  // namespace kryptos
