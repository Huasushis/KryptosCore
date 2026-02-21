// Copyright (c) 2026 Huasushis
// Licensed under the MIT License. See LICENSE file for details.
//
// Unit tests for KryptosCore.
//
// These tests verify deterministic output across platforms. If any test fails
// on a given platform, it means that platform's implementation diverges from
// the reference and passwords will NOT be portable.

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "kryptos/core.h"
#include "kryptos/crypto_utils.h"
#include "kryptos/manager.h"

// ---------------------------------------------------------------------------
// Minimal test framework
// ---------------------------------------------------------------------------

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define ASSERT_EQ(expr, expected)                                           \
  do {                                                                      \
    ++g_tests_run;                                                          \
    auto _val = (expr);                                                     \
    auto _exp = (expected);                                                 \
    if (_val == _exp) {                                                     \
      ++g_tests_passed;                                                     \
    } else {                                                                \
      ++g_tests_failed;                                                     \
      std::cerr << "FAIL [" << __FILE__ << ":" << __LINE__ << "] "         \
                << #expr << "\n"                                            \
                << "  expected: " << _exp << "\n"                           \
                << "  actual:   " << _val << "\n";                          \
    }                                                                       \
  } while (0)

#define ASSERT_TRUE(expr)                                                   \
  do {                                                                      \
    ++g_tests_run;                                                          \
    if (expr) {                                                             \
      ++g_tests_passed;                                                     \
    } else {                                                                \
      ++g_tests_failed;                                                     \
      std::cerr << "FAIL [" << __FILE__ << ":" << __LINE__ << "] "         \
                << #expr << " is false\n";                                  \
    }                                                                       \
  } while (0)

#define ASSERT_THROWS(expr)                                                 \
  do {                                                                      \
    ++g_tests_run;                                                          \
    bool _threw = false;                                                    \
    try {                                                                   \
      (void)(expr);                                                         \
    } catch (...) {                                                         \
      _threw = true;                                                        \
    }                                                                       \
    if (_threw) {                                                           \
      ++g_tests_passed;                                                     \
    } else {                                                                \
      ++g_tests_failed;                                                     \
      std::cerr << "FAIL [" << __FILE__ << ":" << __LINE__ << "] "         \
                << #expr << " did not throw\n";                             \
    }                                                                       \
  } while (0)

// ---------------------------------------------------------------------------
// Helper: hex-encode a raw string for readable comparison.
// ---------------------------------------------------------------------------
static std::string ToHex(const std::string& s) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(s.size() * 2);
  for (unsigned char c : s) {
    out += kHex[c >> 4];
    out += kHex[c & 0x0F];
  }
  return out;
}

// ===========================================================================
// 1. SHA-256
// ===========================================================================

void TestSha256() {
  std::cout << "[sha256]\n";

  // Reference: SHA-256("") = e3b0c44298fc1c...
  ASSERT_EQ(kryptos::Sha256Hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  // SHA-256("abc") = ba7816bf8f01cf...
  ASSERT_EQ(kryptos::Sha256Hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  // SHA-256("hello world")
  ASSERT_EQ(kryptos::Sha256Hex("hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");

  // Raw digest length.
  ASSERT_EQ(kryptos::Sha256Raw("test").size(), size_t(32));
}

// ===========================================================================
// 2. DeterministicStream
// ===========================================================================

void TestDeterministicStream() {
  std::cout << "[deterministic_stream]\n";

  // Same seed must produce the same sequence.
  kryptos::DeterministicStream s1("test_seed");
  kryptos::DeterministicStream s2("test_seed");

  for (int i = 0; i < 200; ++i) {
    ASSERT_EQ(s1.NextByte(), s2.NextByte());
  }

  // Different seeds must produce different sequences (first 4 bytes).
  kryptos::DeterministicStream sa("seed_a");
  kryptos::DeterministicStream sb("seed_b");
  uint32_t a = sa.NextUint32();
  uint32_t b = sb.NextUint32();
  ASSERT_TRUE(a != b);

  // Fixed test vector: first uint32 from "test_seed".
  kryptos::DeterministicStream sv("test_seed");
  uint32_t first = sv.NextUint32();
  // This value is the reference. If it differs on another platform, everything
  // breaks.
  //
  // Compute: SHA256(SHA256_raw("test_seed") || big_endian_64(0)) → first 4
  // bytes as big-endian uint32.
  //
  // We record the value rather than hard-code a manual calculation, then verify
  // it's stable across rebuilds and platforms.
  //
  // Expected: 0x8a3691e0 (captured from reference build)
  // Hard-coded reference value.
  ASSERT_EQ(first, uint32_t(0x5b2a553f));

  // Verify stability across runs.
  kryptos::DeterministicStream sv2("test_seed");
  ASSERT_EQ(sv2.NextUint32(), first);
}

// ===========================================================================
// 3. UniformRandom
// ===========================================================================

void TestUniformRandom() {
  std::cout << "[uniform_random]\n";

  kryptos::DeterministicStream s("uniform_test");

  // All results must be in [0, n).
  for (int i = 0; i < 1000; ++i) {
    size_t r = s.UniformRandom(10);
    ASSERT_TRUE(r < 10);
  }

  // Determinism: same seed, same sequence.
  kryptos::DeterministicStream s1("uniform_det");
  kryptos::DeterministicStream s2("uniform_det");
  for (int i = 0; i < 100; ++i) {
    ASSERT_EQ(s1.UniformRandom(37), s2.UniformRandom(37));
  }

  // Edge case: n=1 always returns 0.
  kryptos::DeterministicStream s3("edge");
  for (int i = 0; i < 10; ++i) {
    ASSERT_EQ(s3.UniformRandom(1), size_t(0));
  }
}

// ===========================================================================
// 4. Password Generation — Determinism & Coverage
// ===========================================================================

void TestPasswordGeneration() {
  std::cout << "[password_generation]\n";

  auto charsets = kryptos::charset::Full();

  // Determinism: same inputs → same output.
  std::string pw1 = kryptos::GeneratePassword("fixed_seed", 16, charsets);
  std::string pw2 = kryptos::GeneratePassword("fixed_seed", 16, charsets);
  ASSERT_EQ(pw1, pw2);
  ASSERT_EQ(static_cast<int>(pw1.size()), 16);
  ASSERT_EQ(pw1, std::string("=)]0]3w-h7GJ2ub+"));

  // Different seeds → different passwords.
  std::string pw3 = kryptos::GeneratePassword("other_seed", 16, charsets);
  ASSERT_TRUE(pw1 != pw3);

  // Coverage: every charset must appear at least once.
  auto check_coverage = [&](const std::string& pw,
                            const std::vector<std::string>& cs) {
    for (const auto& charset : cs) {
      bool found = false;
      for (char c : pw) {
        if (charset.find(c) != std::string::npos) {
          found = true;
          break;
        }
      }
      ASSERT_TRUE(found);
    }
  };

  // Test coverage with many seeds.
  for (int i = 0; i < 50; ++i) {
    std::string seed = "coverage_test_" + std::to_string(i);
    std::string pw = kryptos::GeneratePassword(seed, 8, charsets);
    ASSERT_EQ(static_cast<int>(pw.size()), 8);
    check_coverage(pw, charsets);
  }

  // Minimum length = charsets.size().
  std::string pw_min =
      kryptos::GeneratePassword("min_len", 4, charsets);
  ASSERT_EQ(static_cast<int>(pw_min.size()), 4);
  check_coverage(pw_min, charsets);

  // AlphaNumeric preset.
  auto an = kryptos::charset::AlphaNumeric();
  std::string pw_an = kryptos::GeneratePassword("alphanum_seed", 12, an);
  ASSERT_EQ(static_cast<int>(pw_an.size()), 12);
  check_coverage(pw_an, an);
  ASSERT_EQ(pw_an, std::string("BPq8bi5n6AH8"));

  // Error cases.
  ASSERT_THROWS(kryptos::GeneratePassword("x", 2, charsets));  // length < 4
  ASSERT_THROWS(kryptos::GeneratePassword("x", 5, {}));        // empty charsets
  std::vector<std::string> bad = {"abc", ""};
  ASSERT_THROWS(kryptos::GeneratePassword("x", 5, bad));       // empty charset
}

// ===========================================================================
// 5. Seed Construction
// ===========================================================================

void TestConstructSeed() {
  std::cout << "[construct_seed]\n";

  // Deterministic.
  std::string s1 = kryptos::ConstructSeed("prefix", "github.com",
                                           "uuid123", "user@test.com");
  std::string s2 = kryptos::ConstructSeed("prefix", "github.com",
                                           "uuid123", "user@test.com");
  ASSERT_EQ(s1, s2);
  ASSERT_EQ(s1.size(), size_t(64));  // Hex string.
  ASSERT_EQ(s1,
            "cbf80f19122edb69599a585ece86a5a7dc3c3280a1d56331855756dffae76c79");

  // Different prefix → different seed.
  std::string s3 = kryptos::ConstructSeed("other_prefix", "github.com",
                                           "uuid123", "user@test.com");
  ASSERT_TRUE(s1 != s3);

  // Empty prefix is valid.
  std::string s4 = kryptos::ConstructSeed("", "site", "uuid", "user");
  ASSERT_EQ(s4.size(), size_t(64));

  // Different fields → different seeds.
  std::string s5 = kryptos::ConstructSeed("prefix", "gitlab.com",
                                           "uuid123", "user@test.com");
  ASSERT_TRUE(s1 != s5);
}

// ===========================================================================
// 6. Base64
// ===========================================================================

void TestBase64() {
  std::cout << "[base64]\n";

  // RFC 4648 test vectors.
  ASSERT_EQ(kryptos::crypto::Base64Encode(""), std::string(""));
  ASSERT_EQ(kryptos::crypto::Base64Encode("f"), std::string("Zg=="));
  ASSERT_EQ(kryptos::crypto::Base64Encode("fo"), std::string("Zm8="));
  ASSERT_EQ(kryptos::crypto::Base64Encode("foo"), std::string("Zm9v"));
  ASSERT_EQ(kryptos::crypto::Base64Encode("foob"), std::string("Zm9vYg=="));
  ASSERT_EQ(kryptos::crypto::Base64Encode("fooba"), std::string("Zm9vYmE="));
  ASSERT_EQ(kryptos::crypto::Base64Encode("foobar"), std::string("Zm9vYmFy"));

  // Round-trip.
  ASSERT_EQ(kryptos::crypto::Base64Decode("Zg=="), std::string("f"));
  ASSERT_EQ(kryptos::crypto::Base64Decode("Zm9v"), std::string("foo"));
  ASSERT_EQ(kryptos::crypto::Base64Decode("Zm9vYmFy"), std::string("foobar"));

  // Round-trip with binary data.
  std::string binary;
  for (int i = 0; i < 256; ++i) binary += static_cast<char>(i);
  ASSERT_EQ(kryptos::crypto::Base64Decode(
                kryptos::crypto::Base64Encode(binary)),
            binary);
}

// ===========================================================================
// 7. HMAC-SHA256
// ===========================================================================

void TestHmacSha256() {
  std::cout << "[hmac_sha256]\n";

  // RFC 4231 Test Case 2:
  //   Key  = "Jefe"
  //   Data = "what do ya want for nothing?"
  //   HMAC = 5bdcc146bf60754e6a042426089575c7...
  std::string hmac =
      kryptos::crypto::HmacSha256("Jefe", "what do ya want for nothing?");
  ASSERT_EQ(
      ToHex(hmac),
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

// ===========================================================================
// 8. PBKDF2 (DeriveKey)
// ===========================================================================

void TestDeriveKey() {
  std::cout << "[derive_key]\n";

  // Low iteration count for speed in tests.
  std::string key = kryptos::crypto::DeriveKey("password", "salt", 1);
  ASSERT_EQ(key.size(), size_t(32));

  // PBKDF2-HMAC-SHA256 (not SHA1, so RFC 6070 does not apply).
  // Reference vector captured from this implementation:
  ASSERT_EQ(ToHex(key),
            "120fb6cffcf8b32c43e7225256c4f837"
            "a86548c92ccc35480805987cb70be17b");

  // Determinism.
  std::string key2 = kryptos::crypto::DeriveKey("password", "salt", 1);
  ASSERT_EQ(key, key2);
}

// ===========================================================================
// 9. Encrypt / Decrypt
// ===========================================================================

void TestEncryptDecrypt() {
  std::cout << "[encrypt_decrypt]\n";

  std::string plaintext = "Hello, KryptosCore!";
  std::string key = "test_encryption_key";
  std::string nonce(16, '\x42');  // Fixed nonce for determinism.

  // Encrypt.
  std::string encrypted = kryptos::crypto::Encrypt(plaintext, key, nonce);
  ASSERT_TRUE(encrypted.size() > plaintext.size());  // nonce + tag overhead.
  ASSERT_TRUE(encrypted != plaintext);

  // Decrypt.
  std::string decrypted = kryptos::crypto::Decrypt(encrypted, key);
  ASSERT_EQ(decrypted, plaintext);

  // Wrong key → throws.
  ASSERT_THROWS(kryptos::crypto::Decrypt(encrypted, "wrong_key"));

  // Tampered ciphertext → throws.
  std::string tampered = encrypted;
  tampered[20] ^= 0xFF;  // Flip a byte in the ciphertext.
  ASSERT_THROWS(kryptos::crypto::Decrypt(tampered, key));

  // Empty key passthrough.
  std::string pass = kryptos::crypto::Encrypt(plaintext, "", "");
  ASSERT_EQ(pass, plaintext);
  std::string pass2 = kryptos::crypto::Decrypt(plaintext, "");
  ASSERT_EQ(pass2, plaintext);

  // Determinism: same key + nonce → same ciphertext.
  std::string encrypted2 = kryptos::crypto::Encrypt(plaintext, key, nonce);
  ASSERT_EQ(encrypted, encrypted2);
}

// ===========================================================================
// 10. SecureClear
// ===========================================================================

void TestSecureClear() {
  std::cout << "[secure_clear]\n";

  std::string s = "sensitive_data_12345";
  ASSERT_TRUE(!s.empty());
  kryptos::crypto::SecureClear(s);
  ASSERT_TRUE(s.empty());
}

// ===========================================================================
// 11. Serialisation (Text)
// ===========================================================================

void TestSerialisation() {
  std::cout << "[serialisation]\n";

  kryptos::AccountManager mgr;
  mgr.AddEntry("github.com", "uuid1111", "user@github.com", 20, "full");
  mgr.AddEntry("google.com", "uuid2222", "user@google.com", 16, "alphanum");
  mgr.AddEntry("special\tsite", "uuid3333", "user\nname", 12, "full");

  // Serialise.
  std::string text = mgr.SerializeToText();
  ASSERT_TRUE(!text.empty());
  ASSERT_TRUE(text.find("KRYPTOS:V1") == 0);

  // Deserialise into a new manager.
  kryptos::AccountManager mgr2;
  ASSERT_TRUE(mgr2.DeserializeFromText(text));
  ASSERT_EQ(mgr2.Size(), size_t(3));

  // Verify entries preserved.
  auto* e1 = mgr2.FindEntry("github.com", "user@github.com");
  ASSERT_TRUE(e1 != nullptr);
  ASSERT_EQ(e1->uuid, std::string("uuid1111"));
  ASSERT_EQ(e1->length, 20);
  ASSERT_EQ(e1->charset_preset, std::string("full"));

  auto* e2 = mgr2.FindEntry("google.com", "user@google.com");
  ASSERT_TRUE(e2 != nullptr);
  ASSERT_EQ(e2->charset_preset, std::string("alphanum"));

  // Special characters preserved.
  auto* e3 = mgr2.FindEntry("special\tsite", "user\nname");
  ASSERT_TRUE(e3 != nullptr);
  ASSERT_EQ(e3->uuid, std::string("uuid3333"));

  // Round-trip: serialise again should produce identical output.
  std::string text2 = mgr2.SerializeToText();
  ASSERT_EQ(text, text2);
}

// ===========================================================================
// 12. Export / Import (Base64, encrypted)
// ===========================================================================

void TestExportImport() {
  std::cout << "[export_import]\n";

  kryptos::AccountManager mgr;
  mgr.AddEntry("site-a.com", "aaa111", "alice@a.com", 16, "full");
  mgr.AddEntry("site-b.com", "bbb222", "bob@b.com", 20, "alphanum");

  // --- Unencrypted export/import ---
  std::string b64 = mgr.ExportBase64();
  ASSERT_TRUE(!b64.empty());

  kryptos::AccountManager mgr2;
  mgr2.ImportBase64(b64);
  ASSERT_EQ(mgr2.Size(), size_t(2));
  ASSERT_TRUE(mgr2.FindEntry("site-a.com", "alice@a.com") != nullptr);
  ASSERT_TRUE(mgr2.FindEntry("site-b.com", "bob@b.com") != nullptr);

  // --- Encrypted export/import ---
  std::string key = "export_test_key";
  std::string nonce(16, '\x7F');  // Fixed nonce for test determinism.
  std::string b64_enc = mgr.ExportBase64(key, nonce);
  ASSERT_TRUE(b64_enc != b64);  // Should be different from unencrypted.

  kryptos::AccountManager mgr3;
  mgr3.ImportBase64(b64_enc, key);
  ASSERT_EQ(mgr3.Size(), size_t(2));
  ASSERT_TRUE(mgr3.FindEntry("site-a.com", "alice@a.com") != nullptr);

  // Wrong key → throws.
  kryptos::AccountManager mgr4;
  ASSERT_THROWS(mgr4.ImportBase64(b64_enc, "wrong_key"));

  // --- Merge import ---
  kryptos::AccountManager mgr5;
  mgr5.AddEntry("site-c.com", "ccc333", "charlie@c.com");
  mgr5.ImportBase64(b64, "", true);  // Merge unencrypted.
  ASSERT_EQ(mgr5.Size(), size_t(3));  // 1 existing + 2 imported.

  // Duplicate merge: should not duplicate.
  mgr5.ImportBase64(b64, "", true);
  ASSERT_EQ(mgr5.Size(), size_t(3));
}

// ===========================================================================
// 13. AccountEntry — password generation integration
// ===========================================================================

void TestAccountEntryPassword() {
  std::cout << "[account_entry_password]\n";

  kryptos::AccountEntry entry;
  entry.webname = "example.com";
  entry.uuid = "test_uuid_fixed";
  entry.username = "testuser";
  entry.length = 16;
  entry.charset_preset = "full";

  // Determinism.
  std::string pw1 = entry.GeneratePassword("my_prefix");
  std::string pw2 = entry.GeneratePassword("my_prefix");
  ASSERT_EQ(pw1, pw2);
  ASSERT_EQ(static_cast<int>(pw1.size()), 16);
  ASSERT_EQ(pw1, std::string("AH]xJBI%Z|3dtY9{"));

  // Different prefix → different password.
  std::string pw3 = entry.GeneratePassword("other_prefix");
  ASSERT_TRUE(pw1 != pw3);

  // Empty prefix.
  std::string pw4 = entry.GeneratePassword("");
  ASSERT_EQ(static_cast<int>(pw4.size()), 16);
  ASSERT_EQ(pw4, std::string("5d8_60AHW3f2T9z6"));
}

// ===========================================================================
// 14. Manager — entry management
// ===========================================================================

void TestManagerOperations() {
  std::cout << "[manager_operations]\n";

  kryptos::AccountManager mgr;

  // Add entries.
  ASSERT_TRUE(mgr.AddEntry("site.com", "u1", "user1"));
  ASSERT_TRUE(mgr.AddEntry("site.com", "u2", "user2"));
  ASSERT_EQ(mgr.Size(), size_t(2));

  // Duplicate rejected.
  ASSERT_TRUE(!mgr.AddEntry("site.com", "u3", "user1"));
  ASSERT_EQ(mgr.Size(), size_t(2));

  // FindByWebname.
  auto results = mgr.FindByWebname("site.com");
  ASSERT_EQ(results.size(), size_t(2));

  auto results2 = mgr.FindByWebname("nonexistent.com");
  ASSERT_EQ(results2.size(), size_t(0));

  // FindEntry.
  auto* e = mgr.FindEntry("site.com", "user1");
  ASSERT_TRUE(e != nullptr);
  ASSERT_EQ(e->uuid, std::string("u1"));

  ASSERT_TRUE(mgr.FindEntry("site.com", "user3") == nullptr);

  // RemoveEntry.
  ASSERT_TRUE(mgr.RemoveEntry("site.com", "user1"));
  ASSERT_EQ(mgr.Size(), size_t(1));
  ASSERT_TRUE(mgr.FindEntry("site.com", "user1") == nullptr);

  ASSERT_TRUE(!mgr.RemoveEntry("site.com", "nonexistent"));
}

// ===========================================================================
// 15. Cross-platform reference vectors
// ===========================================================================

void TestCrossPlatformVectors() {
  std::cout << "[cross_platform_vectors]\n";

  // These are the golden test vectors. If ANY of these fail on a platform,
  // that platform is incompatible.

  // Vector 1: SHA-256
  ASSERT_EQ(kryptos::Sha256Hex("KryptosCore"),
            "b1658c43089cb92b6178eca68a1621b4d8ee05046c028e9580c12f25c24ab98d");

  // Vector 2: ConstructSeed
  std::string seed = kryptos::ConstructSeed(
      "master_prefix", "github.com", "abcdef1234567890", "user@example.com");
  ASSERT_EQ(seed,
            "0cf4be51bf95ca0b0c5d511b9d57395d2a0be66aeddfd9bcae3ac7380e48029e");

  // Vector 3: Password from known seed
  auto an = kryptos::charset::AlphaNumeric();
  std::string pw = kryptos::GeneratePassword(seed, 20, an);
  ASSERT_EQ(pw, std::string("4962fMT6y00d23kp5yX3"));

  // Vector 4: HMAC-SHA256 with known inputs
  std::string hmac_hex = ToHex(
      kryptos::crypto::HmacSha256("kryptos_key", "kryptos_message"));
  ASSERT_EQ(hmac_hex,
            "78df78e5759b93bc80e68fe3ad1f9b37dca90bb49378c4d5ff6798b6bcdd09b4");

  // Vector 5: Base64 round-trip of known data (including embedded null)
  std::string b64_input("KryptosCore\x00\x01\x02", 14);
  std::string b64 = kryptos::crypto::Base64Encode(b64_input);
  ASSERT_EQ(b64, std::string("S3J5cHRvc0NvcmUAAQI="));
  ASSERT_EQ(kryptos::crypto::Base64Decode(b64), b64_input);

  // Vector 6: Full pipeline — entry → password
  kryptos::AccountEntry entry;
  entry.webname = "test.example.org";
  entry.uuid = "00000000000000000000000000000000";
  entry.username = "alice@example.org";
  entry.length = 24;
  entry.charset_preset = "full";

  std::string final_pw = entry.GeneratePassword("super_secret");
  ASSERT_EQ(final_pw, std::string(")kXyq27N31q;uUq0F4EyPzZ:"));
  ASSERT_EQ(static_cast<int>(final_pw.size()), 24);
}

// ===========================================================================
// 16. Charset presets
// ===========================================================================

void TestCharsetPresets() {
  std::cout << "[charset_presets]\n";

  auto full = kryptos::charset::Full();
  ASSERT_EQ(full.size(), size_t(4));

  auto an = kryptos::charset::AlphaNumeric();
  ASSERT_EQ(an.size(), size_t(3));

  // FromPresetName.
  auto f2 = kryptos::charset::FromPresetName("full");
  ASSERT_EQ(f2.size(), size_t(4));
  auto a2 = kryptos::charset::FromPresetName("alphanum");
  ASSERT_EQ(a2.size(), size_t(3));
  auto unk = kryptos::charset::FromPresetName("unknown");
  ASSERT_EQ(unk.size(), size_t(4));  // Default to full.
}

// ===========================================================================
// main
// ===========================================================================

int main() {
  std::cout << "=== KryptosCore Unit Tests ===\n\n";

  TestSha256();
  TestDeterministicStream();
  TestUniformRandom();
  TestPasswordGeneration();
  TestConstructSeed();
  TestBase64();
  TestHmacSha256();
  TestDeriveKey();
  TestEncryptDecrypt();
  TestSecureClear();
  TestSerialisation();
  TestExportImport();
  TestAccountEntryPassword();
  TestManagerOperations();
  TestCrossPlatformVectors();
  TestCharsetPresets();

  std::cout << "\n=== Results: " << g_tests_passed << " / " << g_tests_run
            << " passed";
  if (g_tests_failed > 0) {
    std::cout << " (" << g_tests_failed << " FAILED)";
  }
  std::cout << " ===\n";

  return g_tests_failed > 0 ? 1 : 0;
}
