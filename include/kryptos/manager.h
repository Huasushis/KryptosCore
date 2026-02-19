// Copyright (c) 2026 Huasushis
// Licensed under the MIT License. See LICENSE file for details.

#ifndef KRYPTOS_MANAGER_H_
#define KRYPTOS_MANAGER_H_

#include <cstdint>
#include <string>
#include <vector>

namespace kryptos {

// ---------------------------------------------------------------------------
// Account entry
// ---------------------------------------------------------------------------

struct AccountEntry {
  std::string webname;   // Website or application name.
  std::string uuid;      // Random unique identifier (created once, never shown).
  std::string username;  // User-visible identifier (email, phone, username…).
  int length = 16;       // Desired password length.
  std::string charset_preset = "full";  // Charset preset name.

  // Generate the password for this entry.
  std::string GeneratePassword(const std::string& prefix) const;
};

// ---------------------------------------------------------------------------
// Account manager  (pure data — no file I/O or system calls)
// ---------------------------------------------------------------------------

class AccountManager {
 public:
  AccountManager() = default;

  // ---- Entry management ---------------------------------------------------

  // Add a new entry.  |uuid| must be provided by the caller (should be
  // generated from a CSPRNG by the application layer).
  // Returns true on success, false if the (webname, username) pair already
  // exists.
  bool AddEntry(const std::string& webname, const std::string& uuid,
                const std::string& username, int length = 16,
                const std::string& charset_preset = "full");

  // Remove an entry by webname + username.  Returns true if found and removed.
  bool RemoveEntry(const std::string& webname, const std::string& username);

  // Look up entries by webname.
  std::vector<const AccountEntry*> FindByWebname(
      const std::string& webname) const;

  // Look up a single entry by webname + username.  Returns nullptr if not
  // found.
  const AccountEntry* FindEntry(const std::string& webname,
                                const std::string& username) const;

  // Return all entries (read-only).
  const std::vector<AccountEntry>& Entries() const { return entries_; }

  // Return the number of entries.
  size_t Size() const { return entries_.size(); }

  // ---- Serialisation (text format) ----------------------------------------
  // A simple line-based format suitable for local file storage.
  //
  //   KRYPTOS:V1
  //   <entry_count>
  //   <webname>\t<uuid>\t<username>\t<length>\t<charset_preset>
  //   ...

  // Serialise all entries to a text string.
  std::string SerializeToText() const;

  // Load entries from a text string.  Existing entries are cleared.
  // Returns true on success.
  bool DeserializeFromText(const std::string& text);

  // ---- Export / Import (Base64, optionally encrypted) ----------------------

  // Export all data as a Base64 string.
  // If |key| is non-empty, the data is encrypted with that key.
  // |nonce| must be 16 random bytes when |key| is non-empty.
  std::string ExportBase64(const std::string& key = "",
                           const std::string& nonce = "") const;

  // Import data from a Base64 string.
  // If |key| is non-empty, the data is decrypted with that key.
  // Throws std::runtime_error on decryption or parse failure.
  // |merge| — if true, append to existing entries (skip duplicates);
  //           if false, replace all entries.
  void ImportBase64(const std::string& base64, const std::string& key = "",
                    bool merge = false);

 private:
  std::vector<AccountEntry> entries_;
};

}  // namespace kryptos

#endif  // KRYPTOS_MANAGER_H_
