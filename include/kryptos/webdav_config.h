#ifndef KRYPTOS_WEBDAV_CONFIG_H_
#define KRYPTOS_WEBDAV_CONFIG_H_
#include "kryptos/webdav.h"
#include <filesystem>
#include <optional>
namespace kryptos {
struct SavedWebDavConfig {
  WebDavConfig connection;
  bool remember_password = false;
  bool remember_backup_password = false;
};
SavedWebDavConfig LoadWebDavConfig(const std::filesystem::path& file);
void SaveWebDavConfig(const std::filesystem::path& file, const SavedWebDavConfig& config);
std::string WebDavCredentialTarget(const WebDavConfig& config);
std::string WebDavBackupCredentialTarget(const WebDavConfig& config);
std::string CredentialBackendName();
std::optional<std::string> ReadWebDavCredential(const WebDavConfig& config);
void StoreWebDavCredential(const WebDavConfig& config, const std::string& password);
void DeleteWebDavCredential(const WebDavConfig& config);
std::optional<std::string> ReadWebDavBackupCredential(const WebDavConfig& config);
void StoreWebDavBackupCredential(const WebDavConfig& config, const std::string& password);
void DeleteWebDavBackupCredential(const WebDavConfig& config);
}
#endif
