"""Install checksum-pinned CI binaries outside the checkout; no package manager."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]


def verified_payload(data, spec):
    if hashlib.sha256(data).hexdigest() != spec['sha256']:
        raise ValueError('Tool archive SHA-256 mismatch')
    name = spec.get('member')
    if name is None:
        return data
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('Unsafe archive member')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        member = archive.getmember(name)
        if not member.isfile() or member.size > 150 * 1024 * 1024:
            raise ValueError('Unsafe tool archive entry')
        # Only read this member. Never extract an archive to the filesystem.
        return archive.extractfile(member).read()


def install(names, destination):
    destination = destination.resolve()
    if destination == ROOT or ROOT in destination.parents:
        raise ValueError('Tool destination must be outside the checkout')
    lock = json.loads((ROOT/'scripts/ci/tools.lock.json').read_text())['tools']
    machine = {'aarch64': 'arm64', 'amd64': 'x86_64'}.get(platform.machine(), platform.machine())
    target = platform.system().lower() + '-' + machine
    destination.mkdir(parents=True, exist_ok=True)
    for name in names:
        spec = lock[name]['platforms'][target]
        if not spec['url'].startswith('https://github.com/') or not re.fullmatch(r'[0-9a-f]{64}', spec['sha256']):
            raise ValueError('Invalid pinned download')
        with urllib.request.urlopen(spec['url'], timeout=60) as response:
            data = response.read(160 * 1024 * 1024)
        binary = destination/name
        binary.write_bytes(verified_payload(data, spec))
        binary.chmod(0o755)
        args = ['version'] if name == 'gitleaks' else ['version', '--short'] if name == 'compose' else ['--version']
        version = subprocess.run([str(binary), *args], capture_output=True, text=True, check=True)
        if lock[name]['version'] not in version.stdout:
            raise ValueError('Installed tool version mismatch')
        print('PASS | Verified ' + name + ' ' + lock[name]['version'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tools', nargs='+', choices=('ruff', 'actionlint', 'gitleaks', 'compose'))
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    try:
        install(args.tools, args.destination)
    except Exception:
        raise SystemExit('FAIL | Verified tool installation failed; no unverified binary executed') from None
