#include "kryptos/webdav_config.h"
#include "kryptos/crypto_utils.h"
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
namespace fs = std::filesystem;
void Check(bool value) { if (!value) throw std::runtime_error("WebDAV config assertion failed"); }
template<class F> void Throws(F fn) { bool failed = false; try { fn(); } catch (const std::exception&) { failed = true; } Check(failed); }
std::string Read(const fs::path& path) { std::ifstream input(path, std::ios::binary); return {std::istreambuf_iterator<char>(input), {}}; }
int main() {
  try {
    const auto directory = fs::temp_directory_path() / ("kryptos-config-" + std::to_string(std::random_device{}()));
    fs::create_directory(directory);
    struct Cleanup { fs::path dir; ~Cleanup() { std::error_code ignored; fs::remove_all(dir, ignored); } } cleanup{directory};
    const auto file = directory / "kryptos-webdav.conf";
    Check(kryptos::LoadWebDavConfig(file).connection.url.empty());
    kryptos::SavedWebDavConfig config{{"https://dav.example/dav", "Backups/My vault", "user=with tab\tand unicode \xe7\x94\xa8\xe6\x88\xb7", "never-save-this-password"}, true};
    kryptos::SaveWebDavConfig(file, config);
    auto loaded = kryptos::LoadWebDavConfig(file);
    Check(loaded.connection.url == config.connection.url && loaded.connection.directory == config.connection.directory);
    Check(loaded.connection.username == config.connection.username && loaded.connection.password.empty() && loaded.remember_password);
    const auto text = Read(file);
    Check(text.find(config.connection.password) == std::string::npos);
    Check(text.find(kryptos::crypto::Base64Encode(config.connection.password)) == std::string::npos);
    auto another = config.connection;
    another.directory = "another directory";
    Check(kryptos::WebDavCredentialTarget(another) == kryptos::WebDavCredentialTarget(config.connection));
    another.url = "https://other.example";
    Check(kryptos::WebDavCredentialTarget(another) != kryptos::WebDavCredentialTarget(config.connection));
    another = config.connection; another.username += "other";
    Check(kryptos::WebDavCredentialTarget(another) != kryptos::WebDavCredentialTarget(config.connection));
    auto invalid = config; invalid.connection.directory = "../bad";
    Throws([&] { kryptos::SaveWebDavConfig(file, invalid); });
    Check(Read(file) == text);
    config.remember_password = false; config.connection.directory = "new directory";
    kryptos::SaveWebDavConfig(file, config);
    Check(!kryptos::LoadWebDavConfig(file).remember_password);
    Check(kryptos::LoadWebDavConfig(file).connection.directory == "new directory");
    for (const auto& bad : {std::string("bad format"), text + "url=duplicate\n", std::string(32769, 'x')}) {
      { std::ofstream output(file, std::ios::binary | std::ios::trunc); output << bad; }
      Throws([&] { kryptos::LoadWebDavConfig(file); });
    }
    if (std::getenv("KRYPTOS_TEST_SYSTEM_CREDENTIALS")) {
      kryptos::WebDavConfig test{"https://test-" + std::to_string(std::random_device{}()) + ".invalid", "Kryptos", "credential-test", ""};
      struct Clear { kryptos::WebDavConfig config; ~Clear() { try { kryptos::DeleteWebDavCredential(config); } catch (...) {} } } clear{test};
      Check(!kryptos::ReadWebDavCredential(test));
      kryptos::StoreWebDavCredential(test, "temporary test credential");
      auto password = kryptos::ReadWebDavCredential(test);
      Check(password && *password == "temporary test credential"); kryptos::crypto::SecureClear(*password);
      kryptos::DeleteWebDavCredential(test);
      Check(!kryptos::ReadWebDavCredential(test));
      std::cout << "Native credential store round trip passed.\n";
    }
    std::cout << "WebDAV configuration persistence and secret exclusion passed.\n";
  } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
