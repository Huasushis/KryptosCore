// Copyright (c) 2026 Huasushis
// Licensed under the MIT License. See LICENSE file for details.

#include "kryptos/manager.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "kryptos/core.h"
#include "kryptos/crypto_utils.h"

namespace kryptos {

// ---------------------------------------------------------------------------
// Helpers — escape / unescape for the tab-separated text format.
// ---------------------------------------------------------------------------
namespace {

std::string EscapeField(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    switch (c) {
      case '\\':
        out += "\\\\";
        break;
      case '\t':
        out += "\\t";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      default:
        out += c;
    }
  }
  return out;
}

std::string UnescapeField(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '\\' && i + 1 < s.size()) {
      switch (s[i + 1]) {
        case '\\':
          out += '\\';
          ++i;
          break;
        case 't':
          out += '\t';
          ++i;
          break;
        case 'n':
          out += '\n';
          ++i;
          break;
        case 'r':
          out += '\r';
          ++i;
          break;
        default:
          out += s[i];
      }
    } else {
      out += s[i];
    }
  }
  return out;
}

// Split |line| by '\t' into exactly |count| fields.
// Returns false if the wrong number of fields is found.
bool SplitTabs(const std::string& line, size_t count,
               std::vector<std::string>& out) {
  out.clear();
  std::string field;
  for (char c : line) {
    if (c == '\t') {
      out.push_back(field);
      field.clear();
    } else {
      field += c;
    }
  }
  out.push_back(field);
  return out.size() == count;
}

}  // namespace

// ---------------------------------------------------------------------------
// AccountEntry
// ---------------------------------------------------------------------------

std::string AccountEntry::GeneratePassword(const std::string& prefix) const {
  std::string seed = ConstructSeed(prefix, webname, uuid, username);
  auto charsets = charset::FromPresetName(charset_preset);
  return kryptos::GeneratePassword(seed, length, charsets);
}

// ---------------------------------------------------------------------------
// AccountManager — entry management
// ---------------------------------------------------------------------------

bool AccountManager::AddEntry(const std::string& webname,
                              const std::string& uuid,
                              const std::string& username, int length,
                              const std::string& charset_preset) {
  // Reject duplicates.
  if (FindEntry(webname, username) != nullptr) {
    return false;
  }

  AccountEntry entry;
  entry.webname = webname;
  entry.uuid = uuid;
  entry.username = username;
  entry.length = length;
  entry.charset_preset = charset_preset;
  entries_.push_back(std::move(entry));
  return true;
}

bool AccountManager::RemoveEntry(const std::string& webname,
                                 const std::string& username) {
  auto it =
      std::remove_if(entries_.begin(), entries_.end(),
                     [&](const AccountEntry& e) {
                       return e.webname == webname && e.username == username;
                     });
  if (it == entries_.end()) return false;
  entries_.erase(it, entries_.end());
  return true;
}

std::vector<const AccountEntry*> AccountManager::FindByWebname(
    const std::string& webname) const {
  std::vector<const AccountEntry*> results;
  for (const auto& e : entries_) {
    if (e.webname == webname) {
      results.push_back(&e);
    }
  }
  return results;
}

const AccountEntry* AccountManager::FindEntry(
    const std::string& webname, const std::string& username) const {
  for (const auto& e : entries_) {
    if (e.webname == webname && e.username == username) {
      return &e;
    }
  }
  return nullptr;
}

// ---------------------------------------------------------------------------
// Serialisation — text format
// ---------------------------------------------------------------------------

std::string AccountManager::SerializeToText() const {
  std::ostringstream oss;
  oss << "KRYPTOS:V1\n";
  oss << entries_.size() << "\n";
  for (const auto& e : entries_) {
    oss << EscapeField(e.webname) << "\t" << EscapeField(e.uuid) << "\t"
        << EscapeField(e.username) << "\t" << e.length << "\t"
        << EscapeField(e.charset_preset) << "\n";
  }
  return oss.str();
}

bool AccountManager::DeserializeFromText(const std::string& text) {
  std::istringstream iss(text);
  std::string line;

  // Header.
  if (!std::getline(iss, line) || line != "KRYPTOS:V1") return false;

  // Entry count.
  if (!std::getline(iss, line)) return false;
  size_t count = 0;
  try {
    count = std::stoul(line);
  } catch (...) {
    return false;
  }

  std::vector<AccountEntry> new_entries;
  new_entries.reserve(count);

  for (size_t i = 0; i < count; ++i) {
    if (!std::getline(iss, line)) return false;

    std::vector<std::string> fields;
    if (!SplitTabs(line, 5, fields)) return false;

    AccountEntry e;
    e.webname = UnescapeField(fields[0]);
    e.uuid = UnescapeField(fields[1]);
    e.username = UnescapeField(fields[2]);
    try {
      e.length = std::stoi(fields[3]);
    } catch (...) {
      return false;
    }
    e.charset_preset = UnescapeField(fields[4]);
    new_entries.push_back(std::move(e));
  }

  entries_ = std::move(new_entries);
  return true;
}

// ---------------------------------------------------------------------------
// Export / Import (Base64, optionally encrypted)
// ---------------------------------------------------------------------------

std::string AccountManager::ExportBase64(const std::string& key,
                                         const std::string& nonce) const {
  std::string text = SerializeToText();

  if (!key.empty()) {
    text = crypto::Encrypt(text, key, nonce);
  }

  return crypto::Base64Encode(text);
}

void AccountManager::ImportBase64(const std::string& base64,
                                  const std::string& key, bool merge) {
  std::string raw = crypto::Base64Decode(base64);
  if (raw.empty()) {
    throw std::runtime_error("invalid base64 data");
  }

  if (!key.empty()) {
    raw = crypto::Decrypt(raw, key);  // May throw.
  }

  if (merge) {
    // Parse into a temporary manager, then merge.
    AccountManager tmp;
    if (!tmp.DeserializeFromText(raw)) {
      throw std::runtime_error("failed to parse imported data");
    }
    for (const auto& e : tmp.entries_) {
      // Silently skip duplicates.
      AddEntry(e.webname, e.uuid, e.username, e.length, e.charset_preset);
    }
  } else {
    if (!DeserializeFromText(raw)) {
      throw std::runtime_error("failed to parse imported data");
    }
  }
}

}  // namespace kryptos
