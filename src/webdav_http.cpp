// Copyright (c) 2026 Huasushis
// Licensed under the MIT License.
#include "kryptos/webdav.h"
#include <memory>
#include <stdexcept>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#else
#include <curl/curl.h>
#endif

namespace kryptos {
namespace {
constexpr size_t kMaxBytes = 2000000;
#ifdef _WIN32
std::wstring Wide(const std::string& text) {
  const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
  if (!count && !text.empty()) throw std::runtime_error("Invalid UTF-8 WebDAV URL or header");
  std::wstring result(count, 0);
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), count);
  return result;
}
struct Handle {
  HINTERNET value;
  explicit Handle(HINTERNET h) : value(h) { if (!h) throw std::runtime_error("WebDAV connection failed"); }
  ~Handle() { WinHttpCloseHandle(value); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
};
void Check(BOOL ok) { if (!ok) throw std::runtime_error("WebDAV network or TLS request failed (Windows error " + std::to_string(GetLastError()) + ")"); }
#else
size_t BodyCallback(char* data, size_t size, size_t count, void* context) {
  auto& body = *static_cast<std::string*>(context);
  const size_t length = size * count;
  if (length > kMaxBytes - body.size()) return 0;
  body.append(data, length);
  return length;
}
size_t HeaderCallback(char* data, size_t size, size_t count, void* context) {
  const size_t length = size * count;
  std::string line(data, length);
  if (line.size() >= 5 && (line[0] == 'E' || line[0] == 'e') &&
      (line[1] == 'T' || line[1] == 't') && (line[2] == 'A' || line[2] == 'a') &&
      (line[3] == 'G' || line[3] == 'g') && line[4] == ':') {
    auto& etag = *static_cast<std::string*>(context);
    const auto first = line.find_first_not_of(" \t", 5);
    etag = first == std::string::npos ? "" : line.substr(first, line.find_last_not_of(" \t\r\n") - first + 1);
  }
  return length;
}
#endif
}  // namespace

DavResponse WebDavHttpRequest(const std::string& url, const std::string& method,
                             const DavHeaders& headers, const std::string& body) {
  DavResponse result;
#ifdef _WIN32
  const auto wide_url = Wide(url);
  URL_COMPONENTS parts{};
  parts.dwStructSize = sizeof(parts);
  parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength = static_cast<DWORD>(-1);
  Check(WinHttpCrackUrl(wide_url.c_str(), 0, 0, &parts));
  if (parts.nScheme != INTERNET_SCHEME_HTTP && parts.nScheme != INTERNET_SCHEME_HTTPS)
    throw std::runtime_error("WebDAV requires HTTP(S)");
  const std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
  std::wstring path(parts.lpszUrlPath, parts.dwUrlPathLength);
  if (parts.dwExtraInfoLength) path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
  Handle session(WinHttpOpen(L"KryptosCore/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
  Check(WinHttpSetTimeouts(session.value, 30000, 30000, 30000, 30000));
  Handle connection(WinHttpConnect(session.value, host.c_str(), parts.nPort, 0));
  Handle request(WinHttpOpenRequest(connection.value, Wide(method).c_str(), path.c_str(),
      nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
      parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0));
  DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
  Check(WinHttpSetOption(request.value, WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect)));
  std::string header_text;
  for (const auto& header : headers) header_text += header.first + ": " + header.second + "\r\n";
  const auto wide_headers = Wide(header_text);
  Check(WinHttpSendRequest(request.value, wide_headers.c_str(), static_cast<DWORD>(wide_headers.size()),
      body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
      static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0));
  Check(WinHttpReceiveResponse(request.value, nullptr));
  DWORD status = 0, status_size = sizeof(status);
  Check(WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
      WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX));
  result.status = static_cast<int>(status);
  wchar_t etag[4096];
  DWORD etag_size = sizeof(etag);
  if (WinHttpQueryHeaders(request.value, WINHTTP_QUERY_ETAG, WINHTTP_HEADER_NAME_BY_INDEX,
      etag, &etag_size, WINHTTP_NO_HEADER_INDEX)) {
    for (wchar_t ch : std::wstring(etag)) result.etag += static_cast<char>(ch);
  }
  char buffer[8192];
  for (;;) {
    DWORD read = 0;
    Check(WinHttpReadData(request.value, buffer, sizeof(buffer), &read));
    if (!read) break;
    if (read > kMaxBytes - result.body.size()) throw std::runtime_error("WebDAV response is too large");
    result.body.append(buffer, read);
  }
#else
  static const int initialized = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (initialized != CURLE_OK) throw std::runtime_error("Cannot initialize WebDAV HTTP client");
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(curl_easy_init(), curl_easy_cleanup);
  if (!handle) throw std::runtime_error("Cannot create WebDAV HTTP client");
  curl_slist* list = nullptr;
  for (const auto& header : headers) list = curl_slist_append(list, (header.first + ": " + header.second).c_str());
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> owned_headers(list, curl_slist_free_all);
  curl_easy_setopt(handle.get(), CURLOPT_URL, url.c_str());
  curl_easy_setopt(handle.get(), CURLOPT_CUSTOMREQUEST, method.c_str());
  curl_easy_setopt(handle.get(), CURLOPT_HTTPHEADER, list);
  curl_easy_setopt(handle.get(), CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(handle.get(), CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
  curl_easy_setopt(handle.get(), CURLOPT_CONNECTTIMEOUT, 30L);
  curl_easy_setopt(handle.get(), CURLOPT_TIMEOUT, 30L);
  curl_easy_setopt(handle.get(), CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(handle.get(), CURLOPT_WRITEFUNCTION, BodyCallback);
  curl_easy_setopt(handle.get(), CURLOPT_WRITEDATA, &result.body);
  curl_easy_setopt(handle.get(), CURLOPT_HEADERFUNCTION, HeaderCallback);
  curl_easy_setopt(handle.get(), CURLOPT_HEADERDATA, &result.etag);
  if (method != "GET") {
    curl_easy_setopt(handle.get(), CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(handle.get(), CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
  }
  const auto code = curl_easy_perform(handle.get());
  if (code != CURLE_OK) throw std::runtime_error("WebDAV network, TLS or response size error");
  long status = 0;
  curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE, &status);
  result.status = static_cast<int>(status);
#endif
  return result;
}
}  // namespace kryptos
