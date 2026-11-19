"""Exercise the real CLI/HTTP transport against an isolated WebDAV fixture."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
args = parser.parse_args()
binary = Path(args.binary).resolve()
state = {'body': None, 'tag': 0, 'race': False, 'status': 0, 'directories': set(), 'puts': 0}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def reply(self, status, body=b'', **headers):
        self.send_response(status)
        for key, value in headers.items(): self.send_header(key, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def allowed(self):
        if self.headers.get('Authorization') != 'Basic dXNlcjp0b2tlbg==':
            self.reply(401)
            return False
        if state['status']:
            self.reply(state['status'])
            return False
        return True

    def do_MKCOL(self):
        if not self.allowed(): return
        existed = self.path in state['directories']
        state['directories'].add(self.path)
        self.reply(405 if existed else 201)

    def do_PROPFIND(self):
        if not self.allowed(): return
        assert self.headers.get('Depth') == '0'
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.reply(207, b'<d:collection xmlns:d="DAV:"/>')

    def do_GET(self):
        if not self.allowed(): return
        if state['body'] is None: self.reply(404)
        else: self.reply(200, state['body'], ETag='"%d"' % state['tag'])

    def do_PUT(self):
        if not self.allowed(): return
        state['puts'] += 1
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        expected = self.headers.get('If-None-Match') == '*' if state['body'] is None else self.headers.get('If-Match') == '"%d"' % state['tag']
        if state['race'] or not expected:
            self.reply(412)
        else:
            state['body'] = body
            state['tag'] += 1
            self.reply(204)

server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    with tempfile.TemporaryDirectory() as folder:
        devices = []
        for site, username in [('first.example', 'alice'), ('second.example', 'bob')]:
            directory = Path(folder) / username
            directory.mkdir()
            executable = directory / binary.name
            shutil.copy2(binary, executable)
            for dll in binary.parent.glob('*.dll'): shutil.copy2(dll, directory / dll.name)
            (directory / 'kryptos_data.dat').write_bytes(f'KRYPTOS:V1\n1\n{site}\t{username}-uuid\t{username}\t16\tfull\n'.encode())
            devices.append(executable)

        def sync(device, password='backup-password', token='token', choices=''):
            env = dict(os.environ, KRYPTOS_WEBDAV_PASSWORD=token, KRYPTOS_BACKUP_PASSWORD=password)
            return subprocess.run([str(device), 'sync', f'http://127.0.0.1:{server.server_port}/dav/', 'Backups/My vault', 'user'],
                                  env=env, input=choices, text=True, capture_output=True, timeout=45)

        for device in [devices[0], devices[1], devices[0]]:
            result = sync(device)
            assert result.returncode == 0, result.stderr
        assert len(state['directories']) == 2
        assert b'first.example' not in state['body']
        for device in devices:
            text = (device.parent / 'kryptos_data.dat').read_text()
            assert text.startswith('KRYPTOS:V1\n2\n')
            assert 'alice-uuid' in text and 'bob-uuid' in text
        data = devices[0].parent / 'kryptos_data.dat'
        before = data.read_bytes()
        remote_before = state['body']
        puts = state['puts']
        assert sync(devices[0], password='wrong-password').returncode != 0
        assert sync(devices[0], token='wrong-token').returncode != 0
        assert state['puts'] == puts
        state['race'] = True
        assert sync(devices[0]).returncode != 0
        state['race'] = False
        for code in [302, 500]:
            state['status'] = code
            assert sync(devices[0]).returncode != 0
        state['status'] = 0
        assert data.read_bytes() == before and state['body'] == remote_before
        # Create a local conflict against the real encrypted remote snapshot.
        conflict_data = before.replace(b'alice-uuid', b'different-uuid').replace(b'\t16\tfull', b'\t20\talphanum', 1)
        data.write_bytes(conflict_data)
        puts = state['puts']
        for choices in ['', 'c\n', 'r\nn\n', 'l\n']:
            cancelled = sync(devices[0], choices=choices)
            assert cancelled.returncode != 0
            assert data.read_bytes() == conflict_data and state['body'] == remote_before
        assert state['puts'] == puts
        remote_choice = sync(devices[0], choices='invalid\nr\ny\n')
        assert remote_choice.returncode == 0, remote_choice.stderr
        assert 'Account seeds differ' in remote_choice.stdout
        assert 'Apply all choices' in remote_choice.stdout
        assert data.read_bytes() == before
        data.write_bytes(conflict_data)
        state['race'] = True
        assert sync(devices[0], choices='l\ny\n').returncode != 0
        assert data.read_bytes() == conflict_data
        state['race'] = False
        local_choice = sync(devices[0], choices='l\ny\n')
        assert local_choice.returncode == 0, local_choice.stderr
        assert data.read_bytes() == conflict_data
        # The second device must see the chosen local version and may adopt it.
        adopted = sync(devices[1], choices='r\ny\n')
        assert adopted.returncode == 0, adopted.stderr
        assert sorted((devices[1].parent / 'kryptos_data.dat').read_bytes().splitlines()[2:]) == sorted(conflict_data.splitlines()[2:])
        before = conflict_data
        # Configure a device once, then sync without repeating endpoint arguments.
        setup = subprocess.run([str(devices[0]), 'sync-config'],
            input=f'http://127.0.0.1:{server.server_port}/dav/\nBackups/My vault\nuser\nn\nn\n',
            text=True, capture_output=True, timeout=20)
        assert setup.returncode == 0, setup.stderr
        config_path = devices[0].parent / 'kryptos-webdav.conf'
        assert config_path.exists() and b'token' not in config_path.read_bytes()
        env = dict(os.environ, KRYPTOS_WEBDAV_PASSWORD='token', KRYPTOS_BACKUP_PASSWORD='backup-password')
        for name in ('KRYPTOS_WEBDAV_URL', 'KRYPTOS_WEBDAV_DIRECTORY', 'KRYPTOS_WEBDAV_USERNAME'):
            env.pop(name, None)
        reused = subprocess.run([str(devices[0]), 'sync'], env=env, input='', text=True, capture_output=True, timeout=45)
        assert reused.returncode == 0, reused.stderr
        if os.environ.get('KRYPTOS_TEST_SYSTEM_CREDENTIALS'):
            setup = subprocess.run([str(devices[0]), 'sync-config'],
                input='\n\n\ny\ntoken\ny\nbackup-password\n', text=True, capture_output=True, timeout=20)
            assert setup.returncode == 0, setup.stderr
            assert 'unavailable' not in setup.stderr
            assert b'token' not in config_path.read_bytes() and b'backup-password' not in config_path.read_bytes()
            no_secrets = dict(env)
            no_secrets.pop('KRYPTOS_WEBDAV_PASSWORD', None)
            no_secrets.pop('KRYPTOS_BACKUP_PASSWORD', None)
            reused = subprocess.run([str(devices[0]), 'sync'], env=no_secrets, input='', text=True, capture_output=True, timeout=45)
            assert reused.returncode == 0, reused.stderr
            assert 'password / app token:' not in reused.stderr and 'Backup password (' not in reused.stderr
        # A different account must never receive a remembered password.
        cleared = subprocess.run([str(devices[0]), 'sync-config', '--clear'], capture_output=True, text=True, timeout=20)
        assert cleared.returncode == 0, cleared.stderr
        assert not config_path.exists() and data.read_bytes() == before
        if os.environ.get('KRYPTOS_TEST_SYSTEM_CREDENTIALS'):
            # Recreate only the non-secret flags; cleared credentials must not be recoverable.
            import base64
            config_path.write_text('KRYPTOS_WEBDAV_CONFIG_V1\nurl=' + base64.b64encode(f'http://127.0.0.1:{server.server_port}/dav/'.encode()).decode()
                + '\ndirectory=' + base64.b64encode(b'Backups/My vault').decode() + '\nusername=dXNlcg==\nrememberPassword=1\nrememberBackupPassword=1\n')
            missing = subprocess.run([str(devices[0]), 'sync'], env=no_secrets, input='', text=True, capture_output=True, timeout=45)
            assert missing.returncode != 0
            assert 'password / app token:' in missing.stderr and 'Backup password (' in missing.stderr
            config_path.unlink()
        state['body'] = b'corrupt'
        assert sync(devices[0]).returncode != 0
        assert data.read_bytes() == before and state['body'] == b'corrupt'
        print('Real WebDAV transport: merges, local/cloud choices, cancellation, errors and conditional PUT passed')
finally:
    server.shutdown()
    server.server_close()
    thread.join()
