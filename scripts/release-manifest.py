"""Produce a stable manifest from the exact binaries being published."""
import argparse
import hashlib
import re
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--version', required=True)
parser.add_argument('--directory', required=True, type=Path)
args = parser.parse_args()
if not re.fullmatch(r'[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}', args.version):
    raise SystemExit('Expected a stable MAJOR.MINOR.PATCH version.')
lines = ['format=1', 'version=' + args.version]
checksums = []
for platform in ('windows-x86_64', 'linux-x86_64', 'macos-arm64'):
    asset = 'kryptos-' + platform + ('.exe' if platform.startswith('windows') else '')
    checksum = hashlib.sha256((args.directory / asset).read_bytes()).hexdigest()
    lines.extend([f'{platform}.asset={asset}', f'{platform}.sha256={checksum}'])
    checksums.append(f'{checksum}  {asset}')
(args.directory / 'update-manifest.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
(args.directory / 'SHA256SUMS.txt').write_text('\n'.join(checksums) + '\n', encoding='utf-8')
