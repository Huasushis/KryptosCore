#include "kryptos/update.h"
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
#ifdef _WIN32
struct Handle {
  HINTERNET value;
  explicit Handle(HINTERNET h) : value(h) { if (!h) throw std::runtime_error("Update connection failed"); }
  ~Handle() { WinHttpCloseHandle(value); }
};
void Check(BOOL ok) { if (!ok) throw std::runtime_error("Update network or TLS request failed"); }
#else
struct Body { std::string bytes; size_t limit; };
size_t Receive(char* data, size_t size, size_t count, void* context) {
  auto& body = *static_cast<Body*>(context);
  const auto length = size * count;
  if (length > body.limit - body.bytes.size()) return 0;
  body.bytes.append(data, length);
  return length;
}
#endif
}
std::string DownloadUpdate(const std::string& url, size_t max_bytes) {
  if (url.rfind("https://github.com/Huasushis/KryptosCore/releases/", 0) != 0)
    throw std::runtime_error("Updates must come from the official HTTPS releases");
#ifdef _WIN32
  const std::wstring wide(url.begin(), url.end()); // Official release URLs are ASCII.
  URL_COMPONENTS parts{}; parts.dwStructSize = sizeof(parts);
  parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength = static_cast<DWORD>(-1);
  Check(WinHttpCrackUrl(wide.c_str(), 0, 0, &parts));
  const std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
  std::wstring path(parts.lpszUrlPath, parts.dwUrlPathLength);
  if (parts.dwExtraInfoLength) path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
  Handle session(WinHttpOpen(L"KryptosCore-Updater", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
  const int timeout = max_bytes <= 16384 ? 5000 : 60000;
  Check(WinHttpSetTimeouts(session.value, timeout, timeout, timeout, timeout));
  Handle connection(WinHttpConnect(session.value, host.c_str(), parts.nPort, 0));
  Handle request(WinHttpOpenRequest(connection.value, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
  DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
  Check(WinHttpSetOption(request.value, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy)));
  Check(WinHttpSendRequest(request.value, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0));
  Check(WinHttpReceiveResponse(request.value, nullptr));
  DWORD status = 0, status_size = sizeof(status);
  Check(WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX));
  if (status != 200) throw std::runtime_error("No update manifest/asset available (HTTP " + std::to_string(status) + ")");
  std::string bytes;
  char buffer[32768];
  for (;;) {
    DWORD read = 0; Check(WinHttpReadData(request.value, buffer, sizeof(buffer), &read));
    if (!read) break;
    if (read > max_bytes - bytes.size()) throw std::runtime_error("Update download too large");
    bytes.append(buffer, read);
  }
  return bytes;
#else
  static const int initialized = curl_global_init(CURL_GLOBAL_DEFAULT);
  if (initialized != CURLE_OK) throw std::runtime_error("Cannot initialize update client");
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(curl_easy_init(), curl_easy_cleanup);
  if (!handle) throw std::runtime_error("Cannot create update client");
  Body body{{}, max_bytes};
  curl_easy_setopt(handle.get(), CURLOPT_URL, url.c_str());
  curl_easy_setopt(handle.get(), CURLOPT_USERAGENT, "KryptosCore-Updater");
  curl_easy_setopt(handle.get(), CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
  curl_easy_setopt(handle.get(), CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
  curl_easy_setopt(handle.get(), CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(handle.get(), CURLOPT_MAXREDIRS, 5L);
  curl_easy_setopt(handle.get(), CURLOPT_CONNECTTIMEOUT, 5L);
  curl_easy_setopt(handle.get(), CURLOPT_TIMEOUT, max_bytes <= 16384 ? 10L : 180L);
  curl_easy_setopt(handle.get(), CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(handle.get(), CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(handle.get(), CURLOPT_WRITEFUNCTION, Receive);
  curl_easy_setopt(handle.get(), CURLOPT_WRITEDATA, &body);
  if (curl_easy_perform(handle.get()) != CURLE_OK) throw std::runtime_error("Update unavailable: network, TLS, HTTP or size error");
  return body.bytes;
#endif
}
}
