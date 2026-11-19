#include "kryptos/webdav.h"
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
void Check(bool condition) { if (!condition) throw std::runtime_error("WebDAV assertion failed"); }
template<class F> void Throws(F fn) {
  bool failed = false;
  try { fn(); } catch (const std::exception&) { failed = true; }
  Check(failed);
}
}

int main() {
  try {
    kryptos::WebDavConfig config{"https://dav.example/dav/", "Backups/My vault", "user", "token"};
    const auto paths = kryptos::BuildWebDavPaths(config);
    Check(paths.directories.size() == 2);
    Check(paths.file == "https://dav.example/dav/Backups/My%20vault/kryptos-sync.txt");
    for (const std::string directory : {"", "../escape", "a/./b", "bad\\path"}) {
      auto invalid = config; invalid.directory = directory;
      Throws([&] { kryptos::BuildWebDavPaths(invalid); });
    }
    for (const std::string url : {"file:///bad", "https://user:pass@dav.example/", "https://dav.example/?x=1"}) {
      auto invalid = config; invalid.url = url;
      Throws([&] { kryptos::BuildWebDavPaths(invalid); });
    }
    kryptos::AccountManager local, remote;
    local.AddEntry("local.example", "local-uuid", "alice");
    remote.AddEntry("remote.example", "remote-uuid", "bob");
    const std::string key = "backup-password", nonce(16, 'n');
    std::string stored = remote.ExportBase64(key, nonce);
    int put_status = 204, get_status = 200;
    bool created = false, denied = false, directory_is_file = false;
    int puts = 0;
    std::string etag = "\"v1\"";
    kryptos::DavTransport transport = [&](const std::string& url, const std::string& method,
                                        const kryptos::DavHeaders& headers, const std::string& body) {
      Check(headers.at("Authorization") == "Basic dXNlcjp0b2tlbg==");
      if (denied) return kryptos::DavResponse{401, "", ""};
      if (method == "MKCOL") return kryptos::DavResponse{created ? 201 : 405, "", ""};
      if (method == "PROPFIND") {
        Check(headers.at("Depth") == "0");
        return kryptos::DavResponse{207, directory_is_file ? "<d:resourcetype/>" : "<d:collection/>", ""};
      }
      Check(url == paths.file);
      if (method == "GET") return kryptos::DavResponse{get_status, stored, etag};
      Check(method == "PUT");
      ++puts;
      if (get_status == 404) Check(headers.at("If-None-Match") == "*");
      else Check(headers.at("If-Match") == "\"v1\"");
      if (put_status == 204) stored = body;
      return kryptos::DavResponse{put_status, "", ""};
    };
    const auto merged = kryptos::SyncWebDav(local, config, key, nonce, transport);
    Check(local.Size() == 1 && merged.Size() == 2 && puts == 1);
    kryptos::AccountManager decoded;
    decoded.ImportBase64(stored, key);
    Check(decoded.Size() == 2);
    Check(decoded.FindEntry("local.example", "alice")->GeneratePassword("prefix") == local.Entries()[0].GeneratePassword("prefix"));
    const auto before = stored;
    Throws([&] { kryptos::SyncWebDav(local, config, "wrong-password", nonce, transport); });
    Check(stored == before && puts == 1 && local.Size() == 1);
    put_status = 412;
    Throws([&] { kryptos::SyncWebDav(local, config, key, nonce, transport); });
    Check(local.Size() == 1 && stored == before);
    etag = "";
    Throws([&] { kryptos::SyncWebDav(local, config, key, nonce, transport); });
    etag = "W/\"weak\"";
    Throws([&] { kryptos::SyncWebDav(local, config, key, nonce, transport); });
    etag = "\"v1\"";
    denied = true;
    Throws([&] { kryptos::SyncWebDav(local, config, key, nonce, transport); });
    denied = false; directory_is_file = true;
    Throws([&] { kryptos::SyncWebDav(local, config, key, nonce, transport); });
    directory_is_file = false;
    kryptos::AccountManager conflict;
    conflict.AddEntry("local.example", "different-uuid", "alice");
    stored = conflict.ExportBase64(key, nonce);
    const int before_conflict = puts;
    Throws([&] { kryptos::SyncWebDav(local, config, key, nonce, transport); });
    Check(puts == before_conflict);
    created = true; get_status = 404; put_status = 204; stored.clear();
    Check(kryptos::SyncWebDav(local, config, key, nonce, transport).Size() == 1);
    Throws([&] { kryptos::SyncWebDav(local, config, "", nonce, transport); });
    kryptos::AccountManager malformed;
    Check(!malformed.DeserializeFromText("KRYPTOS:V1\n999999999999\n"));
    Check(!malformed.DeserializeFromText("KRYPTOS:V1\n-1\n"));
    Check(!malformed.DeserializeFromText("KRYPTOS:V1\n1junk\n"));
    std::cout << "WebDAV sync checks passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
