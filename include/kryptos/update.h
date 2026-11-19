#ifndef KRYPTOS_UPDATE_H_
#define KRYPTOS_UPDATE_H_
#include <filesystem>
#include <functional>
#include <string>

namespace kryptos {
struct UpdateInfo { std::string version, asset, sha256, url; };
using UpdateDownload = std::function<std::string(const std::string&, size_t)>;
std::string CurrentVersion();
std::string UpdatePlatform();
bool IsNewerVersion(const std::string& candidate, const std::string& current);
UpdateInfo ParseUpdateManifest(const std::string& manifest, const std::string& platform);
UpdateInfo CheckForUpdate(const UpdateDownload& download);
std::string DownloadUpdate(const std::string& url, size_t max_bytes);
// Hash verification precedes all filesystem changes. The account file is never touched.
std::filesystem::path StageUpdate(const UpdateInfo& info, const std::filesystem::path& executable,
                                 const UpdateDownload& download);
// Windows schedules replacement after this process exits; Unix replaces atomically.
void ApplyUpdate(const std::filesystem::path& executable, const std::filesystem::path& staged);
}
#endif
