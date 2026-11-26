"""Read the fixed Day 5 credential directly from the macOS login Keychain."""

import ctypes as c
import os
from pathlib import Path
import sys

from tools.security import require

SERVICE = b'P1 Day 5 Elasticsearch reader'
READER = 'p1_detection_reader'
ACCOUNT = READER.encode('ascii')
ERROR = 'CREDENTIAL_UNAVAILABLE'
REF = c.c_void_p
UINT = c.c_uint32


def bind(library, name, result, *arguments):
    function = getattr(library, name)
    function.argtypes = arguments
    function.restype = result
    return function


def read_keychain_password():
    require(sys.platform == 'darwin', ERROR)
    security = c.CDLL('/System/Library/Frameworks/Security.framework/Security')
    core = c.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    release = bind(core, 'CFRelease', None, REF)
    copy_default = bind(security, 'SecKeychainCopyDefault', c.c_int32, c.POINTER(REF))
    get_path = bind(security, 'SecKeychainGetPath', c.c_int32, REF, c.POINTER(UINT), REF)
    find = bind(security, 'SecKeychainFindGenericPassword', c.c_int32, REF, UINT, c.c_char_p,
                UINT, c.c_char_p, c.POINTER(UINT), c.POINTER(REF), REF)
    free = bind(security, 'SecKeychainItemFreeContent', c.c_int32, REF, REF)

    keychain = REF()
    require(copy_default(c.byref(keychain)) == 0 and keychain.value, ERROR)
    try:
        path = c.create_string_buffer(4096)
        length = UINT(len(path))
        require(get_path(keychain, c.byref(length), path) == 0, ERROR)
        login = Path(os.fsdecode(path.value))
        require(login.parent == Path.home() / 'Library/Keychains' and
                login.name in {'login.keychain-db', 'login.keychain'}, ERROR)

        size, data = UINT(), REF()
        status = find(keychain, len(SERVICE), SERVICE, len(ACCOUNT), ACCOUNT,
                      c.byref(size), c.byref(data), None)
        require(status == 0, ERROR)
        try:
            require(data.value and 0 < size.value <= 1024, ERROR)
            password = c.string_at(data, size.value).decode('utf-8')
            require(password and not any(char in password for char in '\r\n\0'), ERROR)
            return password
        finally:
            free(None, data)
    finally:
        release(keychain)
