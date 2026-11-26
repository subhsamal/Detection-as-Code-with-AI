"""Bounded owner-only local audit events."""

from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import stat

MAX_BYTES = 256 * 1024


class Audit:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()

    def __call__(self, event):
        record = {'time': datetime.now(timezone.utc).isoformat(), **event}
        line = (json.dumps(record, allow_nan=False, separators=(',', ':')) + '\n').encode()
        directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise OSError('Unsafe audit directory')
            fd = os.open('audit.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=directory)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or (
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_size + len(line) > MAX_BYTES
                ):
                    raise OSError('Unsafe or full audit log')
                if os.write(fd, line) != len(line):
                    raise OSError('Incomplete audit write')
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(directory)
