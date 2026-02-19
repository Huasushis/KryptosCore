// Copyright (c) 2026 Huasushis
// Licensed under the MIT License. See LICENSE file for details.
//
// KryptosCore — cross-platform console password manager.
//
// Usage:
//   kryptos                          Interactive mode
//   kryptos <webname>                Generate password (single account)
//   kryptos <webname> <username>     Generate password (specific account)
//   kryptos add                      Add a new entry
//   kryptos list                     List all entries
//   kryptos delete <web> [user]      Delete an entry
//   kryptos export [file]            Export data (Base64)
//   kryptos import <file>            Import data (Base64)
//   kryptos help                     Show this help

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "kryptos/core.h"
#include "kryptos/crypto_utils.h"
#include "kryptos/manager.h"

// ---------------------------------------------------------------------------
// Platform-specific helpers
// ---------------------------------------------------------------------------
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace {

namespace fs = std::filesystem;

// ---- Executable directory -------------------------------------------------

fs::path GetExeDir() {
#ifdef _WIN32
  char buf[MAX_PATH];
  GetModuleFileNameA(nullptr, buf, MAX_PATH);
  return fs::path(buf).parent_path();
#elif defined(__APPLE__)
  // macOS: use _NSGetExecutablePath or /proc/self/exe fallback.
  char buf[1024];
  uint32_t size = sizeof(buf);
  extern int _NSGetExecutablePath(char*, uint32_t*);
  if (_NSGetExecutablePath(buf, &size) == 0) {
    return fs::canonical(buf).parent_path();
  }
  return fs::current_path();
#else
  // Linux.
  return fs::canonical("/proc/self/exe").parent_path();
#endif
}

const std::string kDataFileName = "kryptos_data.dat";

fs::path DataFilePath() { return GetExeDir() / kDataFileName; }

// ---- Silent password input ------------------------------------------------

std::string ReadHiddenInput(const std::string& prompt) {
  std::cerr << prompt;
#ifdef _WIN32
  HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode;
  GetConsoleMode(hStdin, &mode);
  SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);
  std::string input;
  std::getline(std::cin, input);
  SetConsoleMode(hStdin, mode);
#else
  struct termios oldt, newt;
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  std::string input;
  std::getline(std::cin, input);
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
  std::cerr << "\n";
  return input;
}

// ---- Clipboard ------------------------------------------------------------

bool CopyToClipboard(const std::string& text) {
#ifdef _WIN32
  if (!OpenClipboard(nullptr)) return false;
  EmptyClipboard();
  HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
  if (!hMem) {
    CloseClipboard();
    return false;
  }
  char* pMem = static_cast<char*>(GlobalLock(hMem));
  std::memcpy(pMem, text.c_str(), text.size() + 1);
  GlobalUnlock(hMem);
  SetClipboardData(CF_TEXT, hMem);
  CloseClipboard();
  return true;
#elif defined(__APPLE__)
  FILE* pipe = popen("pbcopy", "w");
  if (!pipe) return false;
  fwrite(text.data(), 1, text.size(), pipe);
  pclose(pipe);
  return true;
#else
  // Try xclip first, then xsel.
  FILE* pipe = popen("xclip -selection clipboard 2>/dev/null", "w");
  if (!pipe) {
    pipe = popen("xsel --clipboard --input 2>/dev/null", "w");
  }
  if (!pipe) return false;
  fwrite(text.data(), 1, text.size(), pipe);
  pclose(pipe);
  return true;
#endif
}

// ---- Random UUID generation -----------------------------------------------

std::string GenerateUuid(size_t length = 32) {
  static const char kHex[] = "0123456789abcdef";
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dist(0, 15);

  std::string uuid;
  uuid.reserve(length);
  for (size_t i = 0; i < length; ++i) {
    uuid += kHex[dist(gen)];
  }
  return uuid;
}

// ---- Random nonce for encryption ------------------------------------------

std::string GenerateNonce(size_t length = 16) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dist(0, 255);

  std::string nonce(length, '\0');
  for (size_t i = 0; i < length; ++i) {
    nonce[i] = static_cast<char>(dist(gen));
  }
  return nonce;
}

// ---- File I/O helpers -----------------------------------------------------

bool LoadManager(kryptos::AccountManager& mgr) {
  fs::path path = DataFilePath();
  if (!fs::exists(path)) return true;  // No data yet — OK.

  std::ifstream ifs(path, std::ios::binary);
  if (!ifs) {
    std::cerr << "Error: cannot open " << path << "\n";
    return false;
  }
  std::string content((std::istreambuf_iterator<char>(ifs)),
                      std::istreambuf_iterator<char>());
  if (!mgr.DeserializeFromText(content)) {
    std::cerr << "Error: data file is corrupted.\n";
    return false;
  }
  return true;
}

bool SaveManager(const kryptos::AccountManager& mgr) {
  fs::path path = DataFilePath();
  std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
  if (!ofs) {
    std::cerr << "Error: cannot write to " << path << "\n";
    return false;
  }
  ofs << mgr.SerializeToText();
  return ofs.good();
}

// ---- Print helpers --------------------------------------------------------

void PrintHelp() {
  std::cout
      << "KryptosCore - Deterministic Password Manager\n"
      << "\n"
      << "Usage:\n"
      << "  kryptos                          Interactive mode\n"
      << "  kryptos <webname>                Generate password (single "
         "account)\n"
      << "  kryptos <webname> <username>     Generate password (specific "
         "account)\n"
      << "  kryptos add                      Add a new entry\n"
      << "  kryptos list                     List all entries\n"
      << "  kryptos delete <web> [user]      Delete an entry\n"
      << "  kryptos export [file]            Export data (Base64)\n"
      << "  kryptos import <file>            Import data (Base64)\n"
      << "  kryptos help                     Show this help\n"
      << "\n"
      << "When generating a password, you will be prompted for a prefix\n"
      << "(security passphrase) via hidden input.  The prefix is never "
         "stored.\n";
}

// ---- Password generation & output -----------------------------------------

void OutputPassword(const kryptos::AccountEntry& entry) {
  std::string prefix = ReadHiddenInput("Enter prefix (hidden, press Enter to skip): ");

  std::string password = entry.GeneratePassword(prefix);
  kryptos::crypto::SecureClear(prefix);

  std::cout << "Password: " << password << "\n";

  if (CopyToClipboard(password)) {
    std::cout << "  (copied to clipboard)\n";
  }

  kryptos::crypto::SecureClear(password);
}

// Given a webname, find the entry (may prompt user to choose among multiple).
const kryptos::AccountEntry* ResolveEntry(
    const kryptos::AccountManager& mgr, const std::string& webname,
    const std::string& username_hint = "") {
  auto matches = mgr.FindByWebname(webname);
  if (matches.empty()) {
    std::cerr << "No entry found for \"" << webname << "\".\n";
    return nullptr;
  }

  if (!username_hint.empty()) {
    for (auto* e : matches) {
      if (e->username == username_hint) return e;
    }
    std::cerr << "No entry found for \"" << webname << "\" with username \""
              << username_hint << "\".\n";
    return nullptr;
  }

  if (matches.size() == 1) return matches[0];

  // Multiple matches — let the user choose.
  std::cout << "Multiple accounts for \"" << webname << "\":\n";
  for (size_t i = 0; i < matches.size(); ++i) {
    std::cout << "  " << i << ". " << matches[i]->username << "\n";
  }
  std::cout << "Select [0-" << matches.size() - 1 << "]: ";

  std::string sel;
  std::getline(std::cin, sel);

  // Try to parse as index.
  try {
    size_t idx = std::stoul(sel);
    if (idx < matches.size()) return matches[idx];
  } catch (...) {
  }

  // Try to match as username.
  for (auto* e : matches) {
    if (e->username == sel) return e;
  }

  std::cerr << "Invalid selection.\n";
  return nullptr;
}

// ---- Sub-commands ---------------------------------------------------------

void CmdAdd(kryptos::AccountManager& mgr) {
  std::cout << "--- Add new entry ---\n";

  std::string webname;
  std::cout << "Website/App name: ";
  std::getline(std::cin, webname);
  if (webname.empty()) {
    std::cerr << "Aborted.\n";
    return;
  }

  std::string username;
  std::cout << "Username/Email/Phone: ";
  std::getline(std::cin, username);
  if (username.empty()) {
    std::cerr << "Aborted.\n";
    return;
  }

  std::string len_str;
  std::cout << "Password length [16]: ";
  std::getline(std::cin, len_str);
  int length = 16;
  if (!len_str.empty()) {
    try {
      length = std::stoi(len_str);
    } catch (...) {
      std::cerr << "Invalid length, using default (16).\n";
    }
  }

  std::cout << "Charset preset:\n"
            << "  0. full (lower + upper + digits + symbols) [default]\n"
            << "  1. alphanum (lower + upper + digits)\n"
            << "Select [0-1]: ";
  std::string cs_sel;
  std::getline(std::cin, cs_sel);
  std::string preset = "full";
  if (cs_sel == "1") preset = "alphanum";

  auto charsets = kryptos::charset::FromPresetName(preset);
  if (length < static_cast<int>(charsets.size())) {
    std::cerr << "Password length must be >= " << charsets.size()
              << " for this preset.\n";
    return;
  }

  std::string uuid = GenerateUuid();

  if (!mgr.AddEntry(webname, uuid, username, length, preset)) {
    std::cerr << "Entry already exists for (" << webname << ", " << username
              << ").\n";
    return;
  }

  SaveManager(mgr);
  std::cout << "Entry added successfully.\n";
}

void CmdList(const kryptos::AccountManager& mgr) {
  if (mgr.Size() == 0) {
    std::cout << "No entries.\n";
    return;
  }

  std::cout << "--- All entries ---\n";
  for (size_t i = 0; i < mgr.Entries().size(); ++i) {
    const auto& e = mgr.Entries()[i];
    std::cout << "  " << i << ". " << e.webname << "  |  " << e.username
              << "  |  len=" << e.length << "  |  charset=" << e.charset_preset
              << "\n";
  }
}

void CmdDelete(kryptos::AccountManager& mgr, const std::string& webname,
               const std::string& username_hint) {
  const auto* entry = ResolveEntry(mgr, webname, username_hint);
  if (!entry) return;

  std::cout << "Delete entry: " << entry->webname << " / " << entry->username
            << " ? [y/N]: ";
  std::string confirm;
  std::getline(std::cin, confirm);
  if (confirm != "y" && confirm != "Y") {
    std::cout << "Cancelled.\n";
    return;
  }

  mgr.RemoveEntry(entry->webname, entry->username);
  SaveManager(mgr);
  std::cout << "Entry deleted.\n";
}

void CmdExport(const kryptos::AccountManager& mgr,
               const std::string& file_path) {
  std::string key = ReadHiddenInput(
      "Enter encryption key (press Enter to skip encryption): ");

  std::string nonce;
  std::string base64;
  if (!key.empty()) {
    nonce = GenerateNonce(16);
    base64 = mgr.ExportBase64(key, nonce);
  } else {
    base64 = mgr.ExportBase64();
  }
  kryptos::crypto::SecureClear(key);

  if (file_path.empty()) {
    std::cout << base64 << "\n";
  } else {
    std::ofstream ofs(file_path);
    if (!ofs) {
      std::cerr << "Error: cannot write to " << file_path << "\n";
      return;
    }
    ofs << base64;
    std::cout << "Exported to " << file_path << "\n";
  }
}

void CmdImport(kryptos::AccountManager& mgr, const std::string& file_path) {
  std::ifstream ifs(file_path);
  if (!ifs) {
    std::cerr << "Error: cannot open " << file_path << "\n";
    return;
  }
  std::string base64((std::istreambuf_iterator<char>(ifs)),
                     std::istreambuf_iterator<char>());

  std::string key =
      ReadHiddenInput("Enter decryption key (press Enter if not encrypted): ");

  try {
    mgr.ImportBase64(base64, key, /*merge=*/true);
    kryptos::crypto::SecureClear(key);
    SaveManager(mgr);
    std::cout << "Import successful. Total entries: " << mgr.Size() << "\n";
  } catch (const std::exception& ex) {
    kryptos::crypto::SecureClear(key);
    std::cerr << "Import failed: " << ex.what() << "\n";
  }
}

// ---- Interactive mode -----------------------------------------------------

void InteractiveMode(kryptos::AccountManager& mgr) {
  std::cout << "KryptosCore - Deterministic Password Manager\n\n";

  for (;;) {
    std::cout << "\n  1. Generate password\n"
              << "  2. Add new entry\n"
              << "  3. List entries\n"
              << "  4. Delete entry\n"
              << "  5. Export data\n"
              << "  6. Import data\n"
              << "  0. Exit\n"
              << "\n> ";

    std::string choice;
    if (!std::getline(std::cin, choice)) break;

    if (choice == "0" || choice == "exit" || choice == "quit") break;

    if (choice == "1") {
      std::string webname;
      std::cout << "Website/App name: ";
      std::getline(std::cin, webname);
      const auto* entry = ResolveEntry(mgr, webname);
      if (entry) OutputPassword(*entry);

    } else if (choice == "2") {
      CmdAdd(mgr);

    } else if (choice == "3") {
      CmdList(mgr);

    } else if (choice == "4") {
      std::string webname;
      std::cout << "Website/App name to delete: ";
      std::getline(std::cin, webname);
      CmdDelete(mgr, webname, "");

    } else if (choice == "5") {
      std::string file;
      std::cout << "Export file path (Enter to print to console): ";
      std::getline(std::cin, file);
      CmdExport(mgr, file);

    } else if (choice == "6") {
      std::string file;
      std::cout << "Import file path: ";
      std::getline(std::cin, file);
      if (!file.empty()) CmdImport(mgr, file);

    } else {
      std::cout << "Unknown option. Enter 0 to exit.\n";
    }
  }
}

}  // namespace

// ===========================================================================
// main
// ===========================================================================

int main(int argc, char* argv[]) {
  kryptos::AccountManager mgr;
  if (!LoadManager(mgr)) return 1;

  if (argc < 2) {
    InteractiveMode(mgr);
    return 0;
  }

  std::string cmd = argv[1];

  // ---- Built-in commands --------------------------------------------------
  if (cmd == "help" || cmd == "--help" || cmd == "-h") {
    PrintHelp();
    return 0;
  }

  if (cmd == "add") {
    CmdAdd(mgr);
    return 0;
  }

  if (cmd == "list" || cmd == "ls") {
    CmdList(mgr);
    return 0;
  }

  if (cmd == "delete" || cmd == "del" || cmd == "rm") {
    if (argc < 3) {
      std::cerr << "Usage: kryptos delete <webname> [username]\n";
      return 1;
    }
    std::string user = (argc >= 4) ? argv[3] : "";
    CmdDelete(mgr, argv[2], user);
    return 0;
  }

  if (cmd == "export") {
    std::string file = (argc >= 3) ? argv[2] : "";
    CmdExport(mgr, file);
    return 0;
  }

  if (cmd == "import") {
    if (argc < 3) {
      std::cerr << "Usage: kryptos import <file>\n";
      return 1;
    }
    CmdImport(mgr, argv[2]);
    return 0;
  }

  // ---- Default: treat first argument as webname ---------------------------
  std::string webname = cmd;
  std::string username_hint = (argc >= 3) ? argv[2] : "";

  const auto* entry = ResolveEntry(mgr, webname, username_hint);
  if (!entry) return 1;

  OutputPassword(*entry);
  return 0;
}
