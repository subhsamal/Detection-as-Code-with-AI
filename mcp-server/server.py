"""Local stdio entry point for the fake Elastic Security backend."""

import argparse
import json
import logging
import math
import sys
from time import monotonic
from uuid import uuid4

import anyio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool, ToolAnnotations

from tools.audit import Audit
from tools.security import (
    ALERT_TOOL, MAX_OUTPUT, OUTPUT_SCHEMAS, RULE_ID, RULE_TOOL, SCHEMAS, SPACE, FakeBackend, Fault, ReadTools,
    require, validate,
)

MAX_FRAME = 8 * 1024
METHODS = {'initialize', 'notifications/initialized', 'ping', 'server/discover', 'tools/list', 'tools/call'}
ERRORS = {'UNKNOWN_TOOL', 'INVALID_INPUT', 'DENIED_SCOPE', 'INVALID_CURSOR',
          'NOT_FOUND', 'INVALID_RESPONSE', 'OUTPUT_LIMIT'}
DESCRIPTIONS = {
    RULE_TOOL: 'Return projected synthetic metadata for the approved detection rule.',
    ALERT_TOOL: 'List projected synthetic alerts for the approved detection rule in a bounded UTC window.',
}


def pairs(values):
    output = {}
    for key, value in values:
        require(key not in output, 'INVALID_FRAME')
        output[key] = value
    return output


def finite(value):
    result = float(value)
    require(math.isfinite(result), 'INVALID_FRAME')
    return result


class BoundedInput:
    """Check raw frames before the pinned SDK deserializes them."""

    def __init__(self, stream):
        self.stream = stream

    async def __aiter__(self):
        while True:
            raw = await anyio.to_thread.run_sync(self.stream.readline, MAX_FRAME + 1, abandon_on_cancel=True)
            if not raw:
                return
            require(len(raw) <= MAX_FRAME and raw.endswith(b'\n'), 'INVALID_FRAME')
            line = raw.decode('utf-8')
            frame = json.loads(line, object_pairs_hook=pairs, parse_float=finite, parse_constant=finite)
            require(type(frame) is dict and frame.get('method') in METHODS, 'INVALID_FRAME')
            if 'id' in frame:
                identifier = frame['id']
                require(type(identifier) is int and 0 <= identifier <= 2**53 - 1, 'INVALID_FRAME')
            yield line


def error_result(code, request_id):
    return CallToolResult(
        is_error=True, content=[TextContent(type='text', text=code)],
        structured_content={'error': code, 'request_id': request_id},
    )


def build_server(backend, audit):
    tools = ReadTools(backend)

    async def list_tools(_context, _params):
        return ListToolsResult(tools=[
            Tool(name=name, description=DESCRIPTIONS[name], input_schema=schema, output_schema=OUTPUT_SCHEMAS[name],
                 annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False,
                                             open_world_hint=False, idempotent_hint=True))
            for name, schema in SCHEMAS.items()
        ])

    async def call_tool(_context, params):
        started = monotonic()
        request_id = uuid4().hex
        name = params.name
        event = {'request_id': request_id, 'tool': name if name in SCHEMAS else 'unknown'}

        def record(outcome, count=0):
            try:
                audit({**event, 'outcome': outcome, 'duration_ms': int((monotonic() - started) * 1000),
                       'result_count': count})
            except Exception:
                return False
            return True

        try:
            bounds = validate(name, params.arguments)
        except Fault as error:
            code = str(error)
            return error_result(code if record(code) else 'AUDIT_UNAVAILABLE', request_id)
        event.update(space=SPACE, rule_id=RULE_ID)
        if not record('START'):
            return error_result('AUDIT_UNAVAILABLE', request_id)
        try:
            projected = tools.read(name, params.arguments, bounds)
            result = CallToolResult(content=[TextContent(type='text', text='Synthetic result.')],
                                    structured_content=projected)
            require(len(result.model_dump_json(by_alias=True, exclude_unset=True).encode()) <= MAX_OUTPUT,
                    'OUTPUT_LIMIT')
        except Exception as error:
            code = str(error) if isinstance(error, Fault) and str(error) in ERRORS else 'BACKEND_FAILURE'
            if isinstance(error, (KeyError, TypeError, ValueError)):
                code = 'INVALID_RESPONSE'
            return error_result(code if record(code) else 'AUDIT_UNAVAILABLE', request_id)
        count = 1 if name == RULE_TOOL else len(projected['alerts'])
        if not record('OK', count):
            return error_result('AUDIT_UNAVAILABLE', request_id)
        return result

    return Server('p1-elastic-security-fake', on_list_tools=list_tools, on_call_tool=call_tool)


class Arguments(argparse.ArgumentParser):
    def error(self, _message):
        raise Fault('INVALID_LAUNCH_ARGUMENTS')


async def serve(audit_directory):
    server = build_server(FakeBackend(), Audit(audit_directory))
    async with stdio_server(stdin=BoundedInput(sys.stdin.buffer)) as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())


def main():
    logging.disable(logging.CRITICAL)
    try:
        parser = Arguments(description=__doc__)
        parser.add_argument('--audit-directory', required=True)
        args = parser.parse_args()
        anyio.run(serve, args.audit_directory)
    except Exception:
        print('MCP_STOPPED: invalid launch, input frame or transport failure', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
