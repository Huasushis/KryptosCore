#include "kryptos/webdav_config.h"
#include "kryptos/core.h"
#include "kryptos/crypto_utils.h"
#include <fstream>
#include <map>
#include <random>
#include <stdexcept>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
namespace kryptos {
namespace fs = std::filesystem;
namespace {
void Validate(const WebDavConfig& config) {
  BuildWebDavPaths(config);
  for (const auto* field : {&config.url, &config.directory, &config.username})
    if (field->size() > 4096 || field->find('\0') != std::string::npos)
      throw std::runtime_error("Invalid saved WebDAV configuration");
}
std::string Decode(const std::string& value) {
  auto decoded = crypto::Base64Decode(value);
  if (crypto::Base64Encode(decoded) != value) throw std::runtime_error("Invalid saved WebDAV field");
  return decoded;
}
}
SavedWebDavConfig LoadWebDavConfig(const fs::path& file) {
  SavedWebDavConfig saved;
  if (!fs::exists(file)) return saved;
  if (fs::is_symlink(file) || fs::file_size(file) > 32768) throw std::runtime_error("Invalid saved WebDAV configuration file");
  std::ifstream input(file, std::ios::binary);
  if (!input) throw std::runtime_error("Cannot read saved WebDAV configuration");
  std::string line;
  std::getline(input, line);
  if (!line.empty() && line.back() == '\r') line.pop_back();
  if (line != "KRYPTOS_WEBDAV_CONFIG_V1") throw std::runtime_error("Unsupported WebDAV configuration");
  std::map<std::string, std::string> fields;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    const auto split = line.find('=');
    if (split == std::string::npos || !fields.emplace(line.substr(0, split), line.substr(split + 1)).second)
      throw std::runtime_error("Invalid saved WebDAV configuration");
  }
  for (const auto& field : fields) {
    if (field.first != "url" && field.first != "directory" && field.first != "username" &&
        field.first != "rememberPassword" && field.first != "rememberBackupPassword")
      throw std::runtime_error("Unknown saved WebDAV field");
  }
  if ((fields.size() != 4 && fields.size() != 5) || !fields.count("url") || !fields.count("directory") || !fields.count("username") ||
      (fields["rememberPassword"] != "0" && fields["rememberPassword"] != "1"))
    throw std::runtime_error("Incomplete saved WebDAV configuration");
  saved.connection.url = Decode(fields.at("url"));
  saved.connection.directory = Decode(fields.at("directory"));
  saved.connection.username = Decode(fields.at("username"));
  saved.remember_password = fields["rememberPassword"] == "1";
  saved.remember_backup_password = fields.count("rememberBackupPassword") && fields["rememberBackupPassword"] == "1";
  if (fields.count("rememberBackupPassword") && fields["rememberBackupPassword"] != "0" && fields["rememberBackupPassword"] != "1")
    throw std::runtime_error("Invalid saved WebDAV password setting");
  Validate(saved.connection);
  return saved;
}
void SaveWebDavConfig(const fs::path& file, const SavedWebDavConfig& saved) {
  Validate(saved.connection);
  if (fs::is_symlink(file)) throw std::runtime_error("WebDAV configuration cannot be a symlink");
  auto temporary = file;
  temporary += ".tmp-" + std::to_string(std::random_device{}());
  if (!fs::create_directory(temporary)) throw std::runtime_error("Cannot create temporary WebDAV configuration");
  struct Cleanup { fs::path dir; ~Cleanup() { std::error_code ignored; fs::remove_all(dir, ignored); } } cleanup{temporary};
  fs::permissions(temporary, fs::perms::owner_all);
  const auto staged = temporary / "config";
  std::ofstream output(staged, std::ios::binary | std::ios::trunc);
  output << "KRYPTOS_WEBDAV_CONFIG_V1\nurl=" << crypto::Base64Encode(saved.connection.url)
         << "\ndirectory=" << crypto::Base64Encode(saved.connection.directory)
         << "\nusername=" << crypto::Base64Encode(saved.connection.username)
         << "\nrememberPassword=" << (saved.remember_password ? '1' : '0')
         << "\nrememberBackupPassword=" << (saved.remember_backup_password ? '1' : '0') << '\n';
  output.close();
  if (!output) throw std::runtime_error("Cannot save WebDAV configuration");
  fs::permissions(staged, fs::perms::owner_read | fs::perms::owner_write);
#ifdef _WIN32
  if (!MoveFileExW(staged.c_str(), file.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    throw std::runtime_error("Cannot replace WebDAV configuration");
#else
  fs::rename(staged, file);
#endif
}
std::string WebDavCredentialTarget(const WebDavConfig& config) {
  return "KryptosCore/WebDAV/" + Sha256Hex(config.url + '\0' + config.username);
}
std::string WebDavBackupCredentialTarget(const WebDavConfig& config) {
  return "KryptosCore/WebDAVBackup/" + Sha256Hex(config.url + '\0' + config.directory + '\0' + config.username);
}
}
