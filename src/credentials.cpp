#include "kryptos/webdav_config.h"
#include "kryptos/crypto_utils.h"
#include <stdexcept>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincred.h>
#elif defined(__APPLE__)
#include <Security/Security.h>
#elif defined(KRYPTOS_HAS_LIBSECRET)
#include <libsecret/secret.h>
#endif
namespace kryptos {
namespace {
[[noreturn]] void Unavailable() { throw std::runtime_error("System credential store is unavailable; enter the WebDAV password manually"); }
#ifdef _WIN32
std::wstring Wide(const std::string& text) {
  const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
  if (!size && !text.empty()) throw std::runtime_error("Invalid UTF-8 in WebDAV credentials");
  std::wstring result(size, 0);
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), size);
  return result;
}
#elif defined(KRYPTOS_HAS_LIBSECRET)
const SecretSchema kSchema = {"com.huasushis.KryptosCore.WebDAV", SECRET_SCHEMA_NONE,
    {{"key", SECRET_SCHEMA_ATTRIBUTE_STRING}, {nullptr, SECRET_SCHEMA_ATTRIBUTE_STRING}}};
void CheckError(GError* error) { if (error) { g_error_free(error); Unavailable(); } }
#endif
}
std::string CredentialBackendName() {
#ifdef _WIN32
  return "Windows Credential Manager";
#elif defined(__APPLE__)
  return "macOS Keychain";
#elif defined(KRYPTOS_HAS_LIBSECRET)
  return "Secret Service (desktop keyring)";
#else
  return "unavailable in this build";
#endif
}
std::optional<std::string> ReadWebDavCredential(const WebDavConfig& config) {
  const auto target = WebDavCredentialTarget(config);
#ifdef _WIN32
  PCREDENTIALW credential = nullptr;
  if (!CredReadW(Wide(target).c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
    if (GetLastError() == ERROR_NOT_FOUND) return {}; Unavailable();
  }
  std::string password(reinterpret_cast<char*>(credential->CredentialBlob), credential->CredentialBlobSize);
  CredFree(credential); return password;
#elif defined(__APPLE__)
  const std::string service = "com.huasushis.KryptosCore.WebDAV";
  UInt32 size = 0; void* bytes = nullptr;
  const auto status = SecKeychainFindGenericPassword(nullptr, static_cast<UInt32>(service.size()), service.data(), static_cast<UInt32>(target.size()), target.data(), &size, &bytes, nullptr);
  if (status == errSecItemNotFound) return {};
  if (status != errSecSuccess) Unavailable();
  std::string password(static_cast<char*>(bytes), size); SecKeychainItemFreeContent(nullptr, bytes); return password;
#elif defined(KRYPTOS_HAS_LIBSECRET)
  GError* error = nullptr;
  char* value = secret_password_lookup_sync(&kSchema, nullptr, &error, "key", target.c_str(), nullptr);
  CheckError(error);
  if (!value) return {};
  std::string password(value); secret_password_free(value); return password;
#else
  Unavailable(); return {};
#endif
}
void StoreWebDavCredential(const WebDavConfig& config, const std::string& password) {
  const auto target = WebDavCredentialTarget(config);
  if (password.empty() || password.size() > 4096 || password.find('\0') != std::string::npos)
    throw std::runtime_error("WebDAV password must contain 1-4096 bytes without NUL");
#ifdef _WIN32
  auto name = Wide(target), username = Wide(config.username);
  CREDENTIALW credential{}; credential.Type = CRED_TYPE_GENERIC; credential.TargetName = name.data();
  credential.UserName = username.data(); credential.CredentialBlobSize = static_cast<DWORD>(password.size());
  credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(password.data())); credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
  if (!CredWriteW(&credential, 0)) Unavailable();
#elif defined(__APPLE__)
  const std::string service = "com.huasushis.KryptosCore.WebDAV";
  SecKeychainItemRef item = nullptr;
  auto status = SecKeychainFindGenericPassword(nullptr, static_cast<UInt32>(service.size()), service.data(), static_cast<UInt32>(target.size()), target.data(), nullptr, nullptr, &item);
  if (status == errSecSuccess) { status = SecKeychainItemModifyAttributesAndData(item, nullptr, static_cast<UInt32>(password.size()), password.data()); CFRelease(item); }
  else if (status == errSecItemNotFound) status = SecKeychainAddGenericPassword(nullptr, static_cast<UInt32>(service.size()), service.data(), static_cast<UInt32>(target.size()), target.data(), static_cast<UInt32>(password.size()), password.data(), nullptr);
  if (status != errSecSuccess) Unavailable();
#elif defined(KRYPTOS_HAS_LIBSECRET)
  GError* error = nullptr;
  const auto saved = secret_password_store_sync(&kSchema, SECRET_COLLECTION_DEFAULT, "KryptosCore WebDAV", password.c_str(), nullptr, &error, "key", target.c_str(), nullptr);
  CheckError(error); if (!saved) Unavailable();
#else
  Unavailable();
#endif
}
void DeleteWebDavCredential(const WebDavConfig& config) {
  const auto target = WebDavCredentialTarget(config);
#ifdef _WIN32
  if (!CredDeleteW(Wide(target).c_str(), CRED_TYPE_GENERIC, 0) && GetLastError() != ERROR_NOT_FOUND) Unavailable();
#elif defined(__APPLE__)
  const std::string service = "com.huasushis.KryptosCore.WebDAV";
  SecKeychainItemRef item = nullptr;
  const auto status = SecKeychainFindGenericPassword(nullptr, static_cast<UInt32>(service.size()), service.data(), static_cast<UInt32>(target.size()), target.data(), nullptr, nullptr, &item);
  if (status == errSecItemNotFound) return;
  if (status != errSecSuccess) Unavailable();
  const auto deleted = SecKeychainItemDelete(item); CFRelease(item); if (deleted != errSecSuccess) Unavailable();
#elif defined(KRYPTOS_HAS_LIBSECRET)
  GError* error = nullptr;
  secret_password_clear_sync(&kSchema, nullptr, &error, "key", target.c_str(), nullptr); CheckError(error);
#else
  Unavailable();
#endif
}
}
