# WebDAV sync

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
   stops sync with a conflict. Resolve via existing backup import first.
4. Encrypt the union and conditionally upload. A new file uses `If-None-Match: *`;
   an existing file uses its strong ETag in `If-Match`. HTTP 412 means another
   writer changed it: retry to download and merge again. A server must support
   conditional PUT and return strong ETags. Sync refuses weak/missing tags.
5. Save locally only after upload succeeds. Local writes use temporary-file
   replacement. If the local save fails after upload, retry after fixing storage.

Sync is manual and additive, matching the existing merge-import model. It does
not propagate deletions or automatically choose between edits. A deleted entry
may return from another device. Use existing encrypted export/import to reconcile
or replace datasets intentionally. Wrong passwords, corrupt data, unauthorized
access and conflicts leave the local entries unchanged and do not overwrite the
remote file. Requests have timeouts and a 2 MB payload limit.

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
