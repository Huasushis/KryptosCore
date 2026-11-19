#include "kryptos/update.h"
#include "kryptos/core.h"
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
namespace fs = std::filesystem;
void Check(bool ok) { if (!ok) throw std::runtime_error("Update assertion failed"); }
template<class F> void Throws(F fn) { bool failed = false; try { fn(); } catch (const std::exception&) { failed = true; } Check(failed); }
std::string Read(const fs::path& path) { std::ifstream input(path, std::ios::binary); return {std::istreambuf_iterator<char>(input), {}}; }
int main(int argc, char** argv) {
  try {
    if (argc == 4 && std::string(argv[1]) == "--apply") { kryptos::ApplyUpdate(fs::absolute(argv[2]), fs::absolute(argv[3])); return 0; }
    Check(kryptos::IsNewerVersion("1.10.0", "1.9.9"));
    Check(!kryptos::IsNewerVersion("1.1.0", "1.1.0"));
    Check(!kryptos::IsNewerVersion("1.0.9", "1.1.0"));
    Throws([] { kryptos::IsNewerVersion("1.1.0-rc1", "1.0.0"); });
    const std::string bytes("new program\0binary", 18);
    const auto platform = kryptos::UpdatePlatform();
    const std::string asset = "kryptos-" + platform + (platform == "windows-x86_64" ? ".exe" : "");
    const auto manifest = "format=1\nversion=1.2.3\n" + platform + ".asset=" + asset + "\n" + platform + ".sha256=" + kryptos::Sha256Hex(bytes) + "\n";
    const auto info = kryptos::ParseUpdateManifest(manifest, platform);
    Check(info.url == "https://github.com/Huasushis/KryptosCore/releases/download/v1.2.3/" + asset);
    Throws([&] { kryptos::ParseUpdateManifest(manifest + "version=2.0.0\n", platform); });
    Throws([&] { kryptos::ParseUpdateManifest("format=1\nversion=1.2.3\n", platform); });
    Throws([&] { kryptos::ParseUpdateManifest(std::string(16385, 'x'), platform); });
    Throws([&] { kryptos::ParseUpdateManifest(manifest, "unsupported-platform"); });
    const auto directory = fs::temp_directory_path() / ("kryptos-update-" + std::to_string(std::random_device{}()));
    fs::create_directory(directory);
    struct Cleanup { fs::path dir; ~Cleanup() { std::error_code ignored; fs::remove_all(dir, ignored); } } cleanup{directory};
    const auto executable = directory / "program";
    { std::ofstream(executable) << "old program"; std::ofstream(directory / "kryptos_data.dat") << "account data"; }
    const auto download = [&](const std::string& url, size_t limit) { Check(url == info.url); Check(limit == 64 * 1024 * 1024); return bytes; };
    Throws([&] { kryptos::StageUpdate(info, executable, [](const std::string&, size_t) { return "corrupt"; }); });
    Check(!fs::exists(executable.string() + ".update"));
    Check(Read(executable) == "old program");
    auto invalid = info; invalid.url = "https://attacker.invalid/program";
    Throws([&] { kryptos::StageUpdate(invalid, executable, download); });
    const auto staged = kryptos::StageUpdate(info, executable, download);
    Check(Read(staged) == bytes);
    Throws([&] { kryptos::StageUpdate(info, executable, download); });
    Check(Read(staged) == bytes);
    Check(Read(executable) == "old program");
    Check(Read(directory / "kryptos_data.dat") == "account data");
    std::cout << "Update validation and staging passed.\n";
  } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
