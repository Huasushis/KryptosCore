"""Exercise the real platform replacement helper, including Windows after-exit replacement."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix="kryptos update ' ") as temp:
    root = Path(temp)
    program = root / 'kryptos.exe'
    staged = Path(str(program) + '.update')
    backup = Path(str(program) + '.old')
    data = root / 'kryptos_data.dat'
    data.write_bytes(b'untouched account metadata')
    program.write_bytes(b'first program')
    for old, new in [(b'first program', b'second program'), (b'second program', b'third program')]:
        staged.write_bytes(new)
        subprocess.run([args.binary, '--apply', str(program), str(staged)], check=True, timeout=20)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if program.exists() and program.read_bytes() == new and backup.exists():
                break
            error = Path(str(program) + '.update-error.txt')
            assert not error.exists(), error.read_text(errors='replace') if error.exists() else ''
            time.sleep(0.1)
        assert program.read_bytes() == new
        assert backup.read_bytes() == old
        assert data.read_bytes() == b'untouched account metadata'
    # A missing staged file must fail without removing the installed executable.
    result = subprocess.run([args.binary, '--apply', str(program), str(staged)], timeout=20)
    assert result.returncode != 0
    assert program.read_bytes() == b'third program'
    assert data.read_bytes() == b'untouched account metadata'
print('Real update replacement and rollback copy verified.')
