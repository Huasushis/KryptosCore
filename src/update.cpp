#include "kryptos/update.h"
#include "kryptos/core.h"
#include "kryptos/crypto_utils.h"
#include <array>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <stdexcept>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif
#ifndef KRYPTOS_VERSION
#define KRYPTOS_VERSION "1.0.0"
#endif
namespace kryptos {
namespace fs = std::filesystem;
namespace {
const std::string kReleases = "https://github.com/Huasushis/KryptosCore/releases/";
std::array<unsigned long, 3> Version(const std::string& value) {
  if (!std::regex_match(value, std::regex("[0-9]{1,6}\\.[0-9]{1,6}\\.[0-9]{1,6}")))
    throw std::runtime_error("Unsupported release version");
  std::istringstream input(value);
  std::array<unsigned long, 3> parts{};
  char dot;
  input >> parts[0] >> dot >> parts[1] >> dot >> parts[2];
  return parts;
}
#ifdef _WIN32
std::wstring QuotePS(const fs::path& path) {
  std::wstring result = L"'";
  for (const auto ch : path.wstring()) { result += ch; if (ch == L'\'') result += ch; }
  return result + L"'";
}
#endif
}
std::string CurrentVersion() { return KRYPTOS_VERSION; }
std::string UpdatePlatform() {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
  return "windows-x86_64";
#elif defined(__APPLE__) && defined(__aarch64__)
  return "macos-arm64";
#elif defined(__linux__) && defined(__x86_64__)
  return "linux-x86_64";
#else
  throw std::runtime_error("No release binary for this platform; update from source");
#endif
}
bool IsNewerVersion(const std::string& candidate, const std::string& current) { return Version(candidate) > Version(current); }
UpdateInfo ParseUpdateManifest(const std::string& manifest, const std::string& platform) {
  if (manifest.size() > 16384) throw std::runtime_error("Update manifest too large");
  std::map<std::string, std::string> fields;
  std::istringstream input(manifest);
  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    const auto split = line.find('=');
    if (split == std::string::npos || !fields.emplace(line.substr(0, split), line.substr(split + 1)).second)
      throw std::runtime_error("Invalid update manifest");
  }
  if (fields["format"] != "1") throw std::runtime_error("Unsupported update manifest");
  UpdateInfo info{fields["version"], fields[platform + ".asset"], fields[platform + ".sha256"], ""};
  Version(info.version);
  const auto expected = "kryptos-" + platform + (platform == "windows-x86_64" ? ".exe" : "");
  if (info.asset != expected || !std::regex_match(info.sha256, std::regex("[a-f0-9]{64}")))
    throw std::runtime_error("No verified release asset for this platform");
  info.url = kReleases + "download/v" + info.version + "/" + info.asset;
  return info;
}
UpdateInfo CheckForUpdate(const UpdateDownload& download) {
  return ParseUpdateManifest(download(kReleases + "latest/download/update-manifest.txt", 16384), UpdatePlatform());
}
fs::path StageUpdate(const UpdateInfo& info, const fs::path& executable, const UpdateDownload& download) {
  // Reject paths/URLs supplied by callers outside the official release scheme.
  const auto verified = ParseUpdateManifest("format=1\nversion=" + info.version + "\n" + UpdatePlatform() +
      ".asset=" + info.asset + "\n" + UpdatePlatform() + ".sha256=" + info.sha256 + "\n", UpdatePlatform());
  if (info.url != verified.url) throw std::runtime_error("Invalid release URL");
  const auto bytes = download(info.url, 64 * 1024 * 1024);
  if (bytes.empty() || bytes.size() > 64 * 1024 * 1024 || Sha256Hex(bytes) != info.sha256)
    throw std::runtime_error("Update checksum mismatch; current program was preserved");
  auto staged = executable; staged += ".update";
#ifdef _WIN32
  const auto handle = CreateFileW(staged.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) throw std::runtime_error("Cannot create .update file; check permissions and remove a pending update before retrying");
  DWORD written = 0;
  const bool saved = WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) && written == bytes.size() && FlushFileBuffers(handle);
  CloseHandle(handle);
#else
  const int handle = open(staged.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0700);
  if (handle < 0) throw std::runtime_error("Cannot create .update file; check permissions and pending update");
  size_t offset = 0;
  while (offset < bytes.size()) {
    const auto written = write(handle, bytes.data() + offset, bytes.size() - offset);
    if (written <= 0) break;
    offset += static_cast<size_t>(written);
  }
  const bool saved = offset == bytes.size() && fsync(handle) == 0;
  close(handle);
#endif
  try {
    if (!saved) throw std::runtime_error("Cannot write update next to program (check directory permissions)");
    fs::permissions(staged, fs::status(executable).permissions());
  } catch (...) { std::error_code ignored; fs::remove(staged, ignored); throw; }
  return staged;
}
void ApplyUpdate(const fs::path& executable, const fs::path& staged) {
  auto backup = executable; backup += ".old";
  auto expected = executable; expected += ".update";
  if (staged != expected || fs::is_symlink(staged) || !fs::is_regular_file(staged) || fs::is_symlink(backup))
    throw std::runtime_error("Invalid staged update or backup path");
#ifdef _WIN32
  // EncodedCommand prevents paths, spaces and Unicode from becoming shell code.
  const auto script = L"$ErrorActionPreference='Stop';try{$p=Get-Process -Id " + std::to_wstring(GetCurrentProcessId()) +
      L" -ErrorAction SilentlyContinue;if($p -and (-not $p.WaitForExit(60000))){throw 'Program did not exit'};$exe=" + QuotePS(executable) + L";$new=" + QuotePS(staged) +
      L";$old=" + QuotePS(backup) + L";[IO.File]::Replace($new,$exe,$old)}catch{[IO.File]::WriteAllText(" +
      QuotePS(fs::path(executable.wstring() + L".update-error.txt")) + L",$_.ToString())}";
  const std::string encoded = crypto::Base64Encode(std::string(reinterpret_cast<const char*>(script.data()), script.size() * sizeof(wchar_t)));
  wchar_t system[MAX_PATH];
  if (!GetSystemDirectoryW(system, MAX_PATH)) throw std::runtime_error("Cannot locate Windows PowerShell");
  const auto powershell = fs::path(system) / L"WindowsPowerShell/v1.0/powershell.exe";
  std::wstring command = L"\"" + powershell.wstring() + L"\" -NoProfile -NonInteractive -EncodedCommand " + std::wstring(encoded.begin(), encoded.end());
  STARTUPINFOW startup{}; startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESHOWWINDOW; startup.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(powershell.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process))
    throw std::runtime_error("Cannot start update helper; current program was preserved");
  CloseHandle(process.hThread); CloseHandle(process.hProcess);
#else
  // Keep the old executable; rename of the staged file is atomic on this filesystem.
  fs::copy_file(executable, backup, fs::copy_options::overwrite_existing);
  try { fs::rename(staged, executable); }
  catch (...) { std::error_code ignored; fs::remove(backup, ignored); throw; }
#endif
}
}
