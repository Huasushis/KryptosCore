// Copyright (c) 2026 Huasushis
// Licensed under the MIT License. See LICENSE file for details.

#include "kryptos/core.h"

#include <algorithm>
#include <cassert>
#include <climits>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include "picosha2.h"

namespace kryptos {

// ---------------------------------------------------------------------------
// Helper: raw SHA-256 returning 32 bytes.
// ---------------------------------------------------------------------------
std::string Sha256Raw(const std::string& input) {
  std::vector<uint8_t> hash(picosha2::k_digest_size);
  picosha2::hash256(input.begin(), input.end(), hash.begin(), hash.end());
  return std::string(hash.begin(), hash.end());
}

std::string Sha256Hex(const std::string& input) {
  return picosha2::hash256_hex_string(input);
}

// ---------------------------------------------------------------------------
// DeterministicStream
// ---------------------------------------------------------------------------
DeterministicStream::DeterministicStream(const std::string& seed)
    : seed_(Sha256Raw(seed)), counter_(0), pos_(0) {
  Refill();
}

void DeterministicStream::Refill() {
  // Build input = seed_bytes || big-endian 64-bit counter.
  std::string input = seed_;
  for (int i = 7; i >= 0; --i) {
    input.push_back(static_cast<char>((counter_ >> (i * 8)) & 0xFF));
  }
  ++counter_;

  std::vector<uint8_t> hash(picosha2::k_digest_size);
  picosha2::hash256(input.begin(), input.end(), hash.begin(), hash.end());
  buffer_.assign(hash.begin(), hash.end());
  pos_ = 0;
}

uint8_t DeterministicStream::NextByte() {
  if (pos_ >= buffer_.size()) {
    Refill();
  }
  return buffer_[pos_++];
}

uint32_t DeterministicStream::NextUint32() {
  uint32_t result = 0;
  for (int i = 0; i < 4; ++i) {
    result = (result << 8) | NextByte();
  }
  return result;
}

size_t DeterministicStream::UniformRandom(size_t n) {
  if (n <= 1) return 0;

  // Rejection sampling: accept values in [0, limit) where limit is the
  // largest multiple of n that fits in a uint32_t range (2^32).
  const uint64_t full_range = static_cast<uint64_t>(1) << 32;
  const uint64_t limit = full_range / n * n;

  uint32_t r;
  do {
    r = NextUint32();
  } while (static_cast<uint64_t>(r) >= limit);
  return static_cast<size_t>(r % n);
}

// ---------------------------------------------------------------------------
// Character-set presets
// ---------------------------------------------------------------------------
namespace charset {

const std::string kLowercase = "abcdefghijklmnopqrstuvwxyz";
const std::string kUppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const std::string kDigits = "0123456789";
const std::string kSymbols = "!@#$%^&*()-_=+[]{}|;:,.<>?/~";

std::vector<std::string> Full() {
  return {kLowercase, kUppercase, kDigits, kSymbols};
}

std::vector<std::string> AlphaNumeric() {
  return {kLowercase, kUppercase, kDigits};
}

std::vector<std::string> AlphaNumericSymbol() {
  return {kLowercase, kUppercase, kDigits, kSymbols};
}

std::vector<std::string> FromPresetName(const std::string& name) {
  if (name == "alphanum") return AlphaNumeric();
  if (name == "alphasym" || name == "alphnumsym") return AlphaNumericSymbol();
  // Default to full.
  return Full();
}

std::string ToPresetName(const std::vector<std::string>& charsets) {
  if (charsets == AlphaNumeric()) return "alphanum";
  if (charsets == Full() || charsets == AlphaNumericSymbol()) return "full";
  return "full";
}

}  // namespace charset

// ---------------------------------------------------------------------------
// Password generation
// ---------------------------------------------------------------------------
std::string GeneratePassword(const std::string& seed, int length,
                             const std::vector<std::string>& charsets) {
  if (charsets.empty()) {
    throw std::invalid_argument("charsets must not be empty");
  }
  if (length < static_cast<int>(charsets.size())) {
    throw std::invalid_argument(
        "password length must be >= number of charsets");
  }
  for (const auto& cs : charsets) {
    if (cs.empty()) {
      throw std::invalid_argument("each charset must be non-empty");
    }
  }

  DeterministicStream stream(seed);
  const size_t num_sets = charsets.size();
  std::string result(length, '\0');
  std::vector<bool> used(num_sets, false);   // Whether charset has appeared.
  size_t used_count = 0;

  for (int i = 0; i < length; ++i) {
    const int remaining = length - i;
    const size_t unrepresented = num_sets - used_count;

    size_t chosen = 0;

    // Retry loop: generate weight vector until there is a unique maximum.
    for (;;) {
      std::vector<uint32_t> weights(num_sets);
      for (size_t j = 0; j < num_sets; ++j) {
        weights[j] = stream.NextUint32();
      }

      // If every remaining slot *must* go to an unrepresented charset, mask
      // out the already-used ones.
      if (unrepresented == static_cast<size_t>(remaining)) {
        for (size_t j = 0; j < num_sets; ++j) {
          if (used[j]) weights[j] = 0;
        }
      }

      // Find the maximum value and count how many charsets share it.
      uint32_t max_val = 0;
      size_t max_idx = 0;
      int max_count = 0;
      for (size_t j = 0; j < num_sets; ++j) {
        if (weights[j] > max_val) {
          max_val = weights[j];
          max_idx = j;
          max_count = 1;
        } else if (weights[j] == max_val) {
          ++max_count;
        }
      }

      if (max_count == 1) {
        chosen = max_idx;
        break;
      }
      // Tie — regenerate (extremely unlikely for uint32 values).
    }

    // Pick a character uniformly from the chosen charset.
    size_t char_idx = stream.UniformRandom(charsets[chosen].size());
    result[i] = charsets[chosen][char_idx];

    if (!used[chosen]) {
      used[chosen] = true;
      ++used_count;
    }
  }

  // Fisher-Yates shuffle to eliminate positional bias introduced by the
  // coverage constraint.
  for (int i = length - 1; i > 0; --i) {
    size_t j = stream.UniformRandom(static_cast<size_t>(i) + 1);
    std::swap(result[i], result[j]);
  }

  return result;
}

// ---------------------------------------------------------------------------
// Seed construction
// ---------------------------------------------------------------------------
std::string ConstructSeed(const std::string& prefix,
                          const std::string& webname, const std::string& uuid,
                          const std::string& username) {
  // Hash the prefix first so it cannot be recovered from stored data.
  std::string prefix_hash = Sha256Raw(prefix);

  // Combine with null-byte delimiters to avoid field-boundary ambiguity.
  std::string material;
  material.reserve(prefix_hash.size() + 1 + webname.size() + 1 + uuid.size() +
                   1 + username.size());
  material += prefix_hash;
  material += '\x00';
  material += webname;
  material += '\x00';
  material += uuid;
  material += '\x00';
  material += username;

  return Sha256Hex(material);
}

}  // namespace kryptos
