// Copyright (c) 2026 Huasushis
// Licensed under the MIT License.
#include "kryptos/webdav.h"
#include "kryptos/crypto_utils.h"
#include <algorithm>
#include <regex>
#include <stdexcept>

namespace kryptos {
namespace {
constexpr size_t kMaxBytes = 2000000;
std::string EncodeSegment(const std::string& value) {
  const char hex[] = "0123456789ABCDEF";
  std::string out;
  for (unsigned char ch : value) {
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '~') {
      out += static_cast<char>(ch);
    } else { out += '%'; out += hex[ch >> 4]; out += hex[ch & 15]; }
  }
  return out;
}
std::string IdentityPart(std::string value) {
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) return "";
  value = value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
  for (char& ch : value) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
  return value;
}
std::string Identity(const AccountEntry& e) {
  return IdentityPart(e.webname) + '\0' + IdentityPart(e.username);
}
void ValidateAccounts(const AccountManager& manager) {
  std::map<std::string, bool> identities;
  for (const auto& entry : manager.Entries()) {
    if (entry.webname.empty() || entry.username.empty() || entry.uuid.empty() ||
        entry.length < 4 || entry.length > 128 ||
        (entry.charset_preset != "full" && entry.charset_preset != "alphanum"))
      throw std::runtime_error("Invalid entry in sync data");
    if (!identities.emplace(Identity(entry), true).second)
      throw std::runtime_error("Duplicate account in sync data");
  }
}
AccountManager Merge(const AccountManager& local, const AccountManager& remote,
                     const WebDavConflictResolver& resolve_conflicts) {
  ValidateAccounts(local);
  ValidateAccounts(remote);
  std::vector<AccountEntry> entries = local.Entries();
  std::map<std::string, size_t> positions;
  for (size_t i = 0; i < entries.size(); ++i) positions.emplace(Identity(entries[i]), i);
  std::vector<WebDavConflict> conflicts;
  std::vector<size_t> conflict_positions;
  for (const auto& entry : remote.Entries()) {
    const auto position = positions.find(Identity(entry));
    if (position != positions.end()) {
      const auto& previous = entries[position->second];
      if (previous.webname != entry.webname || previous.username != entry.username ||
          previous.uuid != entry.uuid || previous.length != entry.length ||
          previous.charset_preset != entry.charset_preset) {
        conflicts.push_back({previous, entry});
        conflict_positions.push_back(position->second);
      }
    } else {
      positions.emplace(Identity(entry), entries.size());
      entries.push_back(entry);
    }
  }
  if (entries.size() > 10000) throw std::runtime_error("Too many accounts for sync");
  if (!conflicts.empty()) {
    if (!resolve_conflicts) throw std::runtime_error("Sync conflict: choose local or cloud for each account");
    const auto choices = resolve_conflicts(conflicts);
    if (choices.size() != conflicts.size()) throw std::runtime_error("Choose local or cloud for every sync conflict");
    for (size_t i = 0; i < choices.size(); ++i) {
      if (choices[i] == WebDavChoice::UseRemote) entries[conflict_positions[i]] = conflicts[i].remote;
      else if (choices[i] != WebDavChoice::KeepLocal) throw std::runtime_error("WebDAV sync cancelled");
    }
  }
  AccountManager merged;
  for (const auto& entry : entries) merged.AddEntry(entry.webname, entry.uuid, entry.username, entry.length, entry.charset_preset);
  return merged;
}
}  // namespace

WebDavPaths BuildWebDavPaths(const WebDavConfig& config) {
  std::string path = config.url;
  if (!std::regex_match(path, std::regex(R"(https?://[^/@?#\s\\]+(?:/[^?#\s\\]*)?)")) ||
      config.username.find(':') != std::string::npos)
    throw std::invalid_argument("Use an HTTP(S) WebDAV root URL without credentials, query or fragment");
  while (!path.empty() && path.back() == '/') path.pop_back();
  WebDavPaths out;
  size_t start = 0;
  while (start < config.directory.size()) {
    const auto end = config.directory.find('/', start);
    const auto part = config.directory.substr(start, end == std::string::npos ? end : end - start);
    if (!part.empty()) {
      if (part == "." || part == ".." || std::any_of(part.begin(), part.end(), [](unsigned char c) { return c < 32 || c == 127 || c == '\\'; }))
        throw std::invalid_argument("Sync directory must be relative and cannot contain dot segments or backslashes");
      path += '/' + EncodeSegment(part);
      out.directories.push_back(path + '/');
    }
    if (end == std::string::npos) break;
    start = end + 1;
  }
  if (out.directories.empty()) throw std::invalid_argument("Specify a sync directory, for example Kryptos");
  out.file = path + "/kryptos-sync.txt";
  return out;
}

AccountManager SyncWebDav(const AccountManager& local, const WebDavConfig& config,
                         const std::string& backup_password,
                         const std::string& nonce, const DavTransport& transport,
                         const WebDavConflictResolver& resolve_conflicts) {
  if (backup_password.empty()) throw std::invalid_argument("A separate backup password is required for sync");
  if (nonce.size() != 16) throw std::invalid_argument("Sync requires 16 random nonce bytes");
  const auto paths = BuildWebDavPaths(config);
  const std::string authorization = "Basic " + crypto::Base64Encode(config.username + ':' + config.password);
  auto request = [&](const std::string& url, const std::string& method,
                     DavHeaders headers = {}, const std::string& body = "") {
    headers["Authorization"] = authorization;
    auto response = transport(url, method, headers, body);
    if (response.body.size() > kMaxBytes) throw std::runtime_error("WebDAV response is too large");
    if (response.status == 401 || response.status == 403) throw std::runtime_error("WebDAV authentication or permission denied");
    return response;
  };
  for (const auto& directory : paths.directories) {
    const auto made = request(directory, "MKCOL");
    if (made.status == 405) {
      const auto existing = request(directory, "PROPFIND", {{"Depth", "0"}, {"Content-Type", "application/xml; charset=utf-8"}},
          "<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:resourcetype/></d:prop></d:propfind>");
      if (existing.status != 207 || !std::regex_search(existing.body, std::regex(R"(<([\w.-]+:)?collection(\s|/|>))")))
        throw std::runtime_error("WebDAV sync path is not an accessible directory");
    } else if (made.status != 201) {
      throw std::runtime_error("Cannot create WebDAV directory (HTTP " + std::to_string(made.status) + ")");
    }
  }
  const auto remote = request(paths.file, "GET");
  AccountManager merged;
  merged = Merge(local, {}, {});
  DavHeaders condition;
  if (remote.status == 404) {
    condition["If-None-Match"] = "*";
  } else if (remote.status == 200) {
    if (!std::regex_match(remote.etag, std::regex("\"[^\"\r\n]*\"")))
      throw std::runtime_error("WebDAV must provide a strong ETag for safe sync");
    AccountManager incoming;
    incoming.ImportBase64(remote.body, backup_password);
    merged = Merge(local, incoming, resolve_conflicts);
    condition["If-Match"] = remote.etag;
  } else {
    throw std::runtime_error("Cannot read WebDAV backup (HTTP " + std::to_string(remote.status) + ")");
  }
  const auto encrypted = merged.ExportBase64(backup_password, nonce);
  if (encrypted.size() > kMaxBytes) throw std::runtime_error("Encrypted sync backup is too large");
  condition["Content-Type"] = "text/plain; charset=utf-8";
  const auto uploaded = request(paths.file, "PUT", condition, encrypted);
  if (uploaded.status == 412) throw std::runtime_error("Remote data changed during sync; retry to merge the latest version");
  if (uploaded.status != 200 && uploaded.status != 201 && uploaded.status != 204)
    throw std::runtime_error("Cannot write WebDAV backup (HTTP " + std::to_string(uploaded.status) + ")");
  return merged;
}
}  // namespace kryptos
