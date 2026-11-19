// Copyright (c) 2026 Huasushis
// Licensed under the MIT License.
#ifndef KRYPTOS_WEBDAV_H_
#define KRYPTOS_WEBDAV_H_

#include <functional>
#include <map>
#include <string>
#include <vector>
#include "kryptos/manager.h"

namespace kryptos {
struct WebDavConfig {
  std::string url;
  std::string directory = "Kryptos";  // Relative to url; nested directories allowed.
  std::string username;
  std::string password;
};
struct WebDavPaths {
  std::vector<std::string> directories;
  std::string file;
};
struct DavResponse {
  int status = 0;
  std::string body;
  std::string etag;
};
using DavHeaders = std::map<std::string, std::string>;
using DavTransport = std::function<DavResponse(
    const std::string& url, const std::string& method,
    const DavHeaders& headers, const std::string& body)>;

struct WebDavConflict {
  AccountEntry local;
  AccountEntry remote;
};
enum class WebDavChoice { KeepLocal, UseRemote, Cancel };
// Return one explicit choice per conflict, in order. No resolver means fail
// closed on conflicts. Choices only apply to the downloaded ETag snapshot.
using WebDavConflictResolver = std::function<std::vector<WebDavChoice>(
    const std::vector<WebDavConflict>& conflicts)>;

WebDavPaths BuildWebDavPaths(const WebDavConfig& config);
// Returns a merged copy only after conditional upload succeeds. Never changes
// local on failure. Same identity with different generation data is a conflict.
// Uses the existing encrypted ExportBase64/ImportBase64 format, not device keys.
AccountManager SyncWebDav(const AccountManager& local, const WebDavConfig& config,
                         const std::string& backup_password,
                         const std::string& nonce, const DavTransport& transport,
                         const WebDavConflictResolver& resolve_conflicts = {});
// Platform transport: WinHTTP on Windows, libcurl elsewhere. TLS is verified,
// redirects are rejected, requests time out and responses are capped at 2 MB.
DavResponse WebDavHttpRequest(const std::string& url, const std::string& method,
                             const DavHeaders& headers, const std::string& body);
}  // namespace kryptos
#endif
