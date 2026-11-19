"""Expose CTest failures in public check annotations without requiring log access."""
from pathlib import Path

path = Path('build/Testing/Temporary/LastTest.log')
if path.exists():
    log = path.read_text(errors='replace')[-15000:]
    for offset in range(0, len(log), 2500):
        message = log[offset:offset + 2500].replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
        print('::error title=CTest failure::' + message)
