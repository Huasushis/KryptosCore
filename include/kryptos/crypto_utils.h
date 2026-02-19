// Copyright (c) 2026 Huasushis
// Licensed under the MIT License. See LICENSE file for details.

#ifndef KRYPTOS_CRYPTO_UTILS_H_
#define KRYPTOS_CRYPTO_UTILS_H_

#include <cstdint>
#include <string>
#include <vector>

namespace kryptos {
namespace crypto {

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

// Encode raw bytes to a Base64 string.
std::string Base64Encode(const std::string& input);

// Decode a Base64 string back to raw bytes.  Returns empty string on invalid
// input.
std::string Base64Decode(const std::string& input);

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

// Compute HMAC-SHA256(key, message) and return raw 32-byte digest.
std::string HmacSha256(const std::string& key, const std::string& message);

// ---------------------------------------------------------------------------
// Key derivation  (PBKDF2-HMAC-SHA256, single block)
// ---------------------------------------------------------------------------

// Derive a 32-byte key from |password| and |salt| using |iterations| rounds
// of PBKDF2-HMAC-SHA256.
std::string DeriveKey(const std::string& password, const std::string& salt,
                      int iterations = 100000);

// ---------------------------------------------------------------------------
// Authenticated encryption  (encrypt-then-MAC)
// ---------------------------------------------------------------------------
// Format:   nonce (16 bytes) || ciphertext || HMAC-SHA256 tag (32 bytes)
//
// The nonce must be provided by the caller (ideally from a CSPRNG).
// If |key| is empty, no encryption is performed and the plaintext is returned
// as-is.

std::string Encrypt(const std::string& plaintext, const std::string& key,
                    const std::string& nonce);

// Decrypt and verify.  Returns the plaintext on success.
// Throws std::runtime_error on authentication failure.
// If |key| is empty, returns |ciphertext| as-is.
std::string Decrypt(const std::string& ciphertext, const std::string& key);

// ---------------------------------------------------------------------------
// Secure memory wipe
// ---------------------------------------------------------------------------

// Overwrite |s| with zeros in a way that the compiler cannot optimise away.
void SecureClear(std::string& s);

}  // namespace crypto
}  // namespace kryptos

#endif  // KRYPTOS_CRYPTO_UTILS_H_
