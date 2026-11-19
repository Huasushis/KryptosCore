# WebDAV sync

## Saved connection settings

Run `kryptos sync-config` once (interactive menu 10) to save the WebDAV root URL,
directory and username. Future `kryptos sync` calls and menu 7 reuse them.
Command-line arguments override environment variables, which override saved
settings. Settings are stored in `kryptos-webdav.conf` next to the executable and
are preserved when only the executable is upgraded. The fields are encoded to
support special characters; this file is not encrypted and contains no password.

Setup offers to remember the WebDAV login password in Windows Credential Manager,
macOS Keychain, or Linux Secret Service (libsecret and an unlocked desktop keyring
are required). If the credential store is unavailable, settings can still be saved
and the password entered for each sync. Remembered credentials are tied to the
exact server URL and username; they are never reused for a different connection.
The backup encryption password is not saved.

Use `kryptos sync-config --clear` (menu 11) to delete the saved connection and its
remembered login password; this preserves account metadata and remote backups.
If authentication fails after a password change, run setup again to replace the
stored password. Windows network requests follow the current user's system proxy
settings; no proxy is configured in the WebDAV connection file.

```sh
kryptos sync https://dav.example/remote.php/dav/files/alice Backups/Kryptos alice
```

The URL is an existing WebDAV root. The next argument is a directory **under that
root**, not a local directory. `Backups/Kryptos` is created one level at a time if
missing. Spaces and UTF-8 directory names are URL encoded. Existing directories
are checked with `PROPFIND Depth: 0` after `MKCOL` reports 405.

Omit arguments to enter them interactively, or choose **7. WebDAV sync** in the
menu. The default directory is `Kryptos`. Passwords are read without echo. Use a
WebDAV app token if the provider requires one. Prefer HTTPS: HTTP sends WebDAV
credentials without transport encryption. Redirects are rejected; enter the
provider's final WebDAV URL. TLS certificate validation is always enabled.

Optional environment defaults (use a secret manager for password variables):

| Variable | Meaning |
| --- | --- |
| `KRYPTOS_WEBDAV_URL` | Existing WebDAV root URL |
| `KRYPTOS_WEBDAV_DIRECTORY` | Directory relative to that URL |
| `KRYPTOS_WEBDAV_USERNAME` | WebDAV account |
| `KRYPTOS_WEBDAV_PASSWORD` | WebDAV password or app token |
| `KRYPTOS_BACKUP_PASSWORD` | Separate encryption password shared with Mobile |

## Shared format and behavior

Both clients use `<directory>/kryptos-sync.txt`, containing the existing encrypted
`ExportBase64` format (`KRYPTOS:V1` metadata, PBKDF2-HMAC-SHA256 with 100000 rounds,
16-byte random nonce, authenticated ciphertext). Existing encrypted backups can
be placed at that path to initialize sync. The master prefix, generated passwords,
device encryption keys and WebDAV credentials are not uploaded.

1. Create/check directories.
2. Download the remote backup; only a 404 means a new backup.
3. Authenticate/decrypt and merge additions. Identical accounts are deduplicated.
   Same site/account with different UUID, spelling, password length or charset
   pauses sync for review. The CLI shows both versions and whether account seeds
   differ. For each account, enter `l` to keep local, `r` to use cloud, or `c` to
   cancel. There is no default winner. After choosing every account, confirm with
   `y` to apply and sync. Empty input, EOF, or declining confirmation cancels
   without writing either dataset. Other accounts from both sides are retained.
4. Encrypt the union and conditionally upload. A new file uses `If-None-Match: *`;
   an existing file uses its strong ETag in `If-Match`. HTTP 412 means another
   writer changed it: retry to download and merge again. A server must support
   conditional PUT and return strong ETags. Sync refuses weak/missing tags.
   Changes made by another device while you review also trigger 412. Start sync
   again to review the new versions; previous choices are not reused.
5. Save locally only after upload succeeds. Local writes use temporary-file
   replacement. If the local save fails after upload, retry after fixing storage.

Sync is manual and additive, matching the existing merge-import model. It does
not propagate deletions or automatically choose between edits. A deleted entry
may return from another device; renaming a site/account may leave both names.
Selecting cloud replaces that account's entire generation metadata, including
its UUID. Selecting local publishes that account's local version to the cloud.
Choose the version that generates the password you currently use; a different
seed, name, length or charset can change that password. Wrong passwords, corrupt
data, unauthorized access, cancelled review and incomplete choices leave local
entries unchanged and do not overwrite the remote file. Requests have timeouts
and a 2 MB payload limit. Library consumers can pass a `WebDavConflictResolver`
to `SyncWebDav`; without it, conflicts still fail closed.

## Build

Windows uses system WinHTTP and needs no extra network library. Linux/macOS use
libcurl (`sudo apt-get install libcurl4-openssl-dev` on Debian/Ubuntu; macOS ships
libcurl). The core sync algorithm accepts an injected `DavTransport`, keeping
network I/O out of `AccountManager`.

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```
