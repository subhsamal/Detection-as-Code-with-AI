"""Run one separately approved rule read through the MCP stdio server."""

from contextlib import asynccontextmanager
import json
import logging
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

import anyio
from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client

from server import ERRORS, Arguments
from tools.security import RULE_ID, RULE_TOOL, SPACE, require, rule_projection


REVIEWED_UUID = '3c4ab643-839d-4d94-a2f5-8743aa4b097f'


async def read_once(launch):
    with anyio.fail_after(15):
        async with Client(launch) as client:
            return await client.call_tool(RULE_TOOL, {'space': SPACE, 'rule_id': RULE_ID})


async def authorize_then_read(launch):
    require(sys.stdin.isatty(), 'INTERACTIVE_TERMINAL_REQUIRED')
    timed_out = False
    with TemporaryDirectory(prefix='p1-mcp-keychain-ready-') as directory:
        ready = Path(directory) / 'ready'
        launch.args.extend(['--keychain-ready-file', str(ready)])
        print('KEYCHAIN | approve the macOS prompt with Allow if shown', file=sys.stderr, flush=True)
        async with stdio_client(launch) as streams:
            with anyio.move_on_after(120) as waiting:
                while not ready.is_file():
                    await anyio.sleep(0.1)
            require(not waiting.cancel_called, 'KEYCHAIN_AUTHORIZATION_TIMEOUT')
            print('KEYCHAIN_READY | no Kibana request sent', file=sys.stderr, flush=True)

            @asynccontextmanager
            async def connected_stdio():
                yield streams

            if input('After live approval, type retry to send one GET (anything else stops): ') == 'retry':
                try:
                    return await read_once(connected_stdio())
                except TimeoutError:
                    timed_out = True
    if timed_out:
        raise TimeoutError
    require(False, 'RETRY_NOT_CONFIRMED')


def main():
    logging.disable(logging.CRITICAL)
    try:
        parser = Arguments(description=__doc__)
        parser.add_argument('--execute-approved-get', action='store_true', required=True)
        parser.add_argument('--authorize-then-confirm', action='store_true')
        for name in ('audit-directory', 'ca-file'):
            parser.add_argument(f'--{name}', required=True)
        args = parser.parse_args()
        launch = StdioServerParameters(
            command=sys.executable,
            args=['-B', str(Path(__file__).with_name('server.py').resolve()), '--backend', 'kibana',
                  '--audit-directory', args.audit_directory, '--ca-file', args.ca_file,
                  '--keychain', '--expected-uuid', REVIEWED_UUID],
        )
        result = anyio.run(authorize_then_read if args.authorize_then_confirm else read_once, launch)
        if result.is_error:
            code = result.structured_content['error']
            if code in ERRORS | {'AUDIT_UNAVAILABLE', 'BACKEND_FAILURE'}:
                print(f'BLOCKED: {code}')
                return 1
        else:
            projected = rule_projection(result.structured_content)
            if projected['uuid'] == REVIEWED_UUID:
                print(json.dumps(projected, sort_keys=True))
                return 0
    except TimeoutError:
        print('BLOCKED: BACKEND_TIMEOUT')
        return 1
    except (Exception, KeyboardInterrupt):
        pass
    print('BLOCKED: MCP_PROBE_FAILED')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
