// Copyright (c) 2026 Huasushis
// Licensed under the MIT License. See LICENSE file for details.

#ifndef KRYPTOS_CORE_H_
#define KRYPTOS_CORE_H_

#include <cstdint>
#include <string>
#include <vector>

namespace kryptos {

// Deterministic pseudo-random byte stream based on SHA-256.
//
// Produces an unlimited stream of pseudo-random bytes by repeatedly hashing
// (seed || counter).  The stream is fully deterministic: the same seed always
// yields the same sequence.
class DeterministicStream {
 public:
  explicit DeterministicStream(const std::string& seed);

  // Return the next pseudo-random byte.
  uint8_t NextByte();

  // Return the next pseudo-random 32-bit unsigned integer (big-endian).
  uint32_t NextUint32();

  // Return a uniformly distributed random index in [0, n).
  // Uses rejection sampling to eliminate modulo bias.
  size_t UniformRandom(size_t n);

 private:
  void Refill();

  std::string seed_;
  uint64_t counter_;
  std::vector<uint8_t> buffer_;
  size_t pos_;
};

// ---------------------------------------------------------------------------
// Character-set presets
// ---------------------------------------------------------------------------
namespace charset {

extern const std::string kLowercase;
extern const std::string kUppercase;
extern const std::string kDigits;
extern const std::string kSymbols;

// All four categories (lowercase, uppercase, digits, symbols).
std::vector<std::string> Full();

// Letters and digits.
std::vector<std::string> AlphaNumeric();

// Letters, digits, and symbols.
std::vector<std::string> AlphaNumericSymbol();

// Get charsets by preset name.  Returns Full() for unknown names.
std::vector<std::string> FromPresetName(const std::string& name);

// Get preset name from charsets (best-effort reverse lookup).
std::string ToPresetName(const std::vector<std::string>& charsets);

}  // namespace charset

// ---------------------------------------------------------------------------
// Password generation
// ---------------------------------------------------------------------------

// Generate a deterministic password of the given length.
//
// Every charset in |charsets| is guaranteed to appear at least once in the
// result.  |length| must be >= charsets.size().  The output is then shuffled
// (Fisher-Yates) to eliminate positional bias from the coverage constraint.
std::string GeneratePassword(const std::string& seed, int length,
                             const std::vector<std::string>& charsets);

// Construct the seed for password generation from account details.
//
// The method hashes the prefix independently, then combines it with the
// remaining fields through a second hash to form a fixed-size seed.  This
// ensures the prefix can never be recovered from stored data.
//
//   seed = SHA256( SHA256(prefix) || "\x00" || webname || "\x00"
//                  || uuid || "\x00" || username )
std::string ConstructSeed(const std::string& prefix,
                          const std::string& webname, const std::string& uuid,
                          const std::string& username);

// Convenience wrapper: compute SHA-256 and return hex string.
std::string Sha256Hex(const std::string& input);

// Compute SHA-256 and return raw 32-byte digest.
std::string Sha256Raw(const std::string& input);

}  // namespace kryptos

#endif  // KRYPTOS_CORE_H_
