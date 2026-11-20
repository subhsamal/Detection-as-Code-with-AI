"""Durable, single-target deployment records on a protected local filesystem."""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
from re import fullmatch
import stat
import tempfile

from detections.processing.deployment_plan import canonical, sha256
from scripts.ci.validate import require, strict_json

UNRESOLVED = {'PREPARED', 'APPLYING', 'UNCERTAIN'}
TRANSITIONS = {'PREPARED': {'APPLYING', 'FAILED'}, 'APPLYING': {'VERIFIED', 'UNCERTAIN'}}
MAX_BYTES = 8 * 1024 * 1024


class DeploymentJournal:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()
        self.path = self.directory / 'deployment-journal.json'

    @contextmanager
    def locked(self, *, shared=False):
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    'Journal directory must be owned by the current user and mode 0700')
            fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
            yield fd
        finally:
            os.close(fd)

    def load(self, directory_fd, binding):
        try:
            fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        except FileNotFoundError:
            return []
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                    stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                    'Journal must be an owned mode-0600 regular file')
            raw = stream.read(MAX_BYTES + 1)
        require(len(raw) <= MAX_BYTES, 'Journal size limit exceeded')
        try:
            envelope = strict_json(raw)
        except (ValueError, RecursionError):
            raise ValueError('Malformed deployment journal') from None
        try:
            data = envelope['data']
            require(envelope['sha256'] == sha256(canonical(data)), 'Journal checksum mismatch')
            require(data['schema_version'] == 1 and isinstance(data['records'], list),
                    'Unsupported journal format')
            require(canonical(data['binding']) == canonical(binding), 'Journal target binding mismatch')
            for index, record in enumerate(data['records']):
                history = record['states']
                require(isinstance(history, list) and history and history[0] == 'PREPARED'
                        and all_transitions_valid(history), 'Invalid journal transitions')
                require(index == len(data['records']) - 1 or history[-1] not in UNRESOLVED,
                        'Invalid journal record order')
                before = record['before']
                require(record['operation'] in {'apply', 'rollback'} and
                        before['id'] == binding['uuid'] and type(before['revision']) is int and
                        before['revision'] >= 0 and
                        canonical(record['plan']['target']) == canonical(binding['target']),
                        'Invalid journal snapshot binding')
                for payload in (before['payload'], record['desired']):
                    require(payload['rule_id'] == binding['rule_id'] and
                            payload['enabled'] is False and payload['actions'] == [],
                            'Invalid journal payload')
                require(record['plan_sha256'] == sha256(canonical(record['plan'])) and
                        record['payload_sha256'] == sha256(canonical(record['desired'])),
                        'Invalid journal plan or payload digest')
                if history[-1] == 'VERIFIED':
                    require(fullmatch(r'[a-f0-9]{64}', record['result_sha256']),
                            'Invalid journal result digest')
            return data['records']
        except (KeyError, TypeError, AttributeError, IndexError, RecursionError):
            raise ValueError('Invalid deployment journal structure') from None

    def save(self, directory_fd, binding, records):
        data = {'schema_version': 1, 'binding': binding, 'records': records}
        raw = canonical({'sha256': sha256(canonical(data)), 'data': data})
        require(len(raw) <= MAX_BYTES, 'Journal size limit exceeded')
        fd, temporary = tempfile.mkstemp(prefix='.deployment-journal-', dir=self.directory)
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(Path(temporary).name, self.path.name,
                       src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            try:
                os.unlink(Path(temporary).name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass

    def advance(self, directory_fd, binding, records, destination, **fields):
        record = records[-1]
        require(destination in TRANSITIONS.get(record['states'][-1], set()), 'Invalid journal transition')
        updated = {**record, **fields, 'states': [*record['states'], destination]}
        self.save(directory_fd, binding, [*records[:-1], updated])
        records[-1] = updated


def all_transitions_valid(history):
    return all(after in TRANSITIONS.get(before, set()) for before, after in zip(history, history[1:]))
