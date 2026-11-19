# Program updates

Replacing only `kryptos` / `kryptos.exe` in the existing directory preserves
`kryptos_data.dat`. Do not replace the whole directory or delete the data file.
The metadata format and password algorithm are unchanged by this iteration.

## Built-in updater

```
kryptos version
kryptos update --check
kryptos update
kryptos update --auto on
kryptos update --auto off
```

Interactive menu 8 checks and offers to install; menu 9 toggles checks at startup.
Automatic checking is off by default and never installs anything. It runs only
when opening the interactive menu, so one-shot password commands stay offline.
Settings live in `kryptos-update-settings.txt` next to the program.

The updater downloads the latest stable release manifest from the official
GitHub repository. The download URL is constructed from the stable version and
the platform asset name. HTTPS is required, redirects cannot downgrade to HTTP,
downloads are bounded, and SHA-256 must match before a staged file is written.
The manifest and checksum trust the repository's HTTPS release channel; they
are not an independent publisher signature.

After you confirm, the program stages a verified `.update` file next to itself.
Linux/macOS replace the executable by rename. On Windows a hidden PowerShell
helper waits for the process to exit, then uses File.Replace. Run Kryptos again
after it exits. The previous executable is kept as `.old` (replaced on the next
successful update). Windows helper failures leave `.update-error.txt`; a failed
replacement preserves the installed executable. Account data is never opened
or modified by the updater. Installation requires a writable program directory.
Unsupported architectures must update from source.

For rollback, close Kryptos and replace the executable with its `.old` copy.
For manual updates, download the matching asset from GitHub Releases, verify
`SHA256SUMS.txt`, close Kryptos and replace only the executable in place.

## Release publication

The existing main-branch release workflow embeds the generated release version
in each binary, then publishes `update-manifest.txt` and `SHA256SUMS.txt` alongside
the Windows x86_64, Linux x86_64 and macOS arm64 binaries. Existing releases that
predate manifests cannot serve the updater; the first release containing this
change must be installed manually. Feature-branch CI does not publish releases.
