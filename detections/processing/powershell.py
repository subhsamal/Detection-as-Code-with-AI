"""Offline, deliberately limited PowerShell evidence classifier. Never evaluates code."""
import argparse
import base64
import binascii
from copy import deepcopy
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
import re

MAX_SCRIPT_BYTES = 65536
MAX_ENCODED_CHARS = 87384
MAX_TOKENS = 4096
MAX_CMD_DELAY_SECONDS = 120
OFFICE = {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
          'msaccess.exe', 'mspub.exe', 'onenote.exe'}
POWERSHELL = {'powershell.exe', 'pwsh.exe'}
ENCODED_OPTIONS = {'-encodedcommand', '-enc', '-ec', '-e'}


class Unsupported(ValueError):
    pass


def tokenize(script):
    """Separate literals/comments from commands; reject unrecognized syntax."""
    if len(script.encode('utf-8')) > MAX_SCRIPT_BYTES:
        raise Unsupported('script_size_limit')
    tokens, i = [], 0
    while i < len(script):
        c = script[i]
        if c in ' \t\r':
            i += 1
            continue
        if c == '#':
            end = script.find('\n', i)
            i = len(script) if end < 0 else end
            continue
        if c in "'\"":
            quote, value = c, ''
            i += 1
            while i < len(script):
                c = script[i]
                if c == quote:
                    if quote == "'" and i + 1 < len(script) and script[i + 1] == "'":
                        value += "'"
                        i += 2
                        continue
                    i += 1
                    break
                if quote == '"' and c in '$`':
                    raise Unsupported('dynamic_string')
                value += c
                i += 1
            else:
                raise Unsupported('unterminated_string')
            tokens.append(('string', value))
        elif c in '();|=.\n':
            tokens.append(('symbol', ';' if c == '\n' else c))
            i += 1
        else:
            match = re.match(r'\$[A-Za-z_][A-Za-z0-9_]*|-?[A-Za-z_][A-Za-z0-9_-]*', script[i:])
            if not match:
                raise Unsupported('unsupported_token')
            value = match.group().lower()
            tokens.append(('variable' if value.startswith('$') else 'word', value))
            i += len(match.group())
        if len(tokens) > MAX_TOKENS:
            raise Unsupported('token_limit')
    return tokens


class Reader:
    def __init__(self, tokens):
        self.tokens, self.pos = tokens, 0

    def take(self, value=None, kind=None):
        if self.pos >= len(self.tokens):
            raise Unsupported('incomplete_expression')
        token = self.tokens[self.pos]
        if kind is None and value in {'(', ')', ';', '|', '=', '.'}:
            kind = 'symbol'
        if (value is not None and token[1] != value) or (kind and token[0] != kind):
            raise Unsupported('unsupported_structure')
        self.pos += 1
        return token[1]

    def peek(self, value):
        return self.pos < len(self.tokens) and self.tokens[self.pos][1] == value

    def done(self):
        if self.pos != len(self.tokens):
            raise Unsupported('unsupported_remainder')

    def download(self, depth=0):
        if depth > 16:
            raise Unsupported('nesting_limit')
        if self.peek('('):
            self.take('(')
            if self.peek('new-object'):
                self.take('new-object', 'word')
                parts = [self.take(kind='word')]
                while self.peek('.'):
                    self.take('.')
                    parts.append(self.take(kind='word'))
                if '.'.join(parts) not in {'net.webclient', 'system.net.webclient'}:
                    raise Unsupported('unsupported_constructor')
                self.take(')'); self.take('.'); self.take('downloadstring', 'word')
                self.take('('); self.url(); self.take(')')
                result = 'text'
            else:
                result = self.download(depth + 1)
                self.take(')')
            if self.peek('.'):
                self.take('.'); self.take('content', 'word')
                if result != 'response':
                    raise Unsupported('invalid_content_access')
                result = 'text'
            return result
        self.take('invoke-webrequest', 'word')
        if self.peek('-uri'):
            self.take('-uri', 'word')
        self.url()
        return 'response'

    def url(self):
        url = self.take(kind='string')
        if not re.fullmatch(r'https?://[^\s]+', url, re.IGNORECASE):
            raise Unsupported('unsupported_url')

    def execution(self):
        command = self.take(kind='word')
        if command not in {'iex', 'invoke-expression'}:
            raise Unsupported('unsupported_execution')


def statements(tokens):
    parts, current, depth = [], [], 0
    for token in tokens:
        if token == ('symbol', '('):
            depth += 1
        elif token == ('symbol', ')'):
            depth -= 1
            if depth < 0:
                raise Unsupported('unbalanced_parentheses')
        if token == ('symbol', ';'):
            if depth:
                # Newlines inside parentheses are outside the initial grammar.
                raise Unsupported('separator_in_expression')
            if current:
                parts.append(current); current = []
        else:
            current.append(token)
    if depth:
        raise Unsupported('unbalanced_parentheses')
    if current:
        parts.append(current)
    return parts


def analyze_script(script):
    """Return instruction-level evidence, never a claim of successful execution."""
    try:
        parts = statements(tokenize(script))
        if not parts:
            return {'status': 'no_download', 'pattern': 'empty_or_comments'}
        if len(parts) > 2:
            raise Unsupported('too_many_statements')
        first = Reader(parts[0])
        if first.peek('write-output'):
            first.take('write-output', 'word'); first.take(kind='string'); first.done()
            if len(parts) != 1:
                raise Unsupported('unsupported_remainder')
            return {'status': 'no_download', 'pattern': 'literal_output'}
        variable = None
        if first.tokens[0][0] == 'variable':
            variable = first.take(kind='variable'); first.take('=')
        if not variable and (first.peek('iex') or first.peek('invoke-expression')):
            first.execution()
            if first.download() != 'text':
                raise Unsupported('execution_requires_downloaded_text')
            first.done()
            if len(parts) != 1:
                raise Unsupported('unsupported_remainder')
            return {'status': 'download_and_execute', 'pattern': 'direct_argument'}
        kind = first.download()
        if first.peek('|') and not variable:
            first.take('|'); first.execution(); first.done()
            if kind != 'text' or len(parts) != 1:
                raise Unsupported('unsupported_pipeline')
            return {'status': 'download_and_execute', 'pattern': 'direct_pipeline'}
        first.done()
        if len(parts) == 1:
            return {'status': 'download_only', 'pattern': 'download_only'}
        if not variable or kind != 'text':
            raise Unsupported('unlinked_execution')
        second = Reader(parts[1]); second.execution()
        bracket = second.peek('(')
        if bracket:
            second.take('(')
        if second.take(kind='variable') != variable:
            raise Unsupported('unrelated_variable')
        if bracket:
            second.take(')')
        second.done()
        return {'status': 'download_and_execute', 'pattern': 'single_variable'}
    except (Unsupported, UnicodeError) as error:
        return {'status': 'unknown', 'reason': str(error)}


def decode_command(process):
    """Only normalized argv is supported; raw Windows command-line parsing is not guessed."""
    args = process.get('args')
    if not isinstance(args, list) or not args or not all(isinstance(a, str) for a in args):
        raise Unsupported('normalized_arguments_missing')
    image = args[0].replace('/', '\\').rsplit('\\', 1)[-1].lower()
    if image != process.get('name', '').lower():
        raise Unsupported('argument_image_mismatch')
    i = 1
    while i < len(args):
        option = args[i].lower()
        if option in ENCODED_OPTIONS:
            if i + 2 != len(args):
                raise Unsupported('missing_value_or_trailing_arguments')
            value = args[i + 1]
            if len(value) > MAX_ENCODED_CHARS:
                raise Unsupported('encoded_size_limit')
            try:
                raw = base64.b64decode(value, validate=True)
                if not raw or len(raw) > MAX_SCRIPT_BYTES:
                    raise Unsupported('decoded_size_limit')
                text = raw.decode('utf-16-le')
            except (ValueError, binascii.Error, UnicodeError):
                raise Unsupported('invalid_base64_or_utf16') from None
            if '\x00' in text:
                raise Unsupported('nul_in_script')
            return text
        if option in {'-noprofile', '-nop', '-noninteractive', '-noni'}:
            i += 1
        elif option in {'-windowstyle', '-w', '-executionpolicy', '-ep'}:
            if i + 1 >= len(args):
                raise Unsupported('missing_option_value')
            allowed = ({'hidden', 'normal', 'minimized', 'maximized'} if option in {'-w', '-windowstyle'}
                       else {'bypass', 'restricted', 'allsigned', 'remotesigned', 'unrestricted', 'default', 'undefined'})
            if args[i + 1].lower() not in allowed:
                raise Unsupported('unsupported_option_value')
            i += 2
        elif option in {'-file', '-command', '-c'}:
            raise Unsupported('not_supported_encoded_invocation')
        else:
            raise Unsupported('unsupported_launcher_option')
    raise Unsupported('encoded_option_missing')


def timestamp(event):
    value = event.get('@timestamp')
    if not isinstance(value, str):
        raise Unsupported('timestamp_missing')
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError()
        return stamp.astimezone(timezone.utc)
    except ValueError:
        raise Unsupported('invalid_timestamp') from None


def process_start(event):
    data = event.get('event', {})
    def contains(field, value):
        entry = data.get(field)
        return entry == value or isinstance(entry, list) and value in entry
    return contains('category', 'process') and contains('type', 'start')


def prepare_events(events):
    """Offline batch: original records retained; one derived output per candidate source."""
    if not isinstance(events, list):
        raise ValueError('input_must_be_event_list')
    # Invalid JSON envelopes are input errors, not invented process classifications.
    for event in events:
        if not isinstance(event, dict):
            raise ValueError('event_must_be_object')
        for field in ['host', 'process', 'event']:
            if not isinstance(event.get(field, {}), dict):
                raise ValueError('event_fields_must_be_objects')
        if not isinstance(event.get('host', {}).get('os', {}), dict):
            raise ValueError('host_os_must_be_object')
        if not isinstance(event.get('process', {}).get('parent', {}), dict):
            raise ValueError('process_parent_must_be_object')
        if not isinstance(event.get('process', {}).get('name', ''), str):
            raise ValueError('process_name_must_be_string')
    index = {}
    for event in events:
        key = (event.get('host', {}).get('id'), event.get('process', {}).get('entity_id'))
        if all(isinstance(v, str) and v for v in key):
            index.setdefault(key, []).append(event)
    output = []
    for event in events:
        process = event.get('process', {})
        if process.get('name', '').lower() not in POWERSHELL:
            continue
        result = deepcopy(event)
        evidence = {'status': 'unknown', 'reason': 'not_analyzed'}
        derived = {'analysis_version': 'p1-ps-001-local-v1', 'lineage': {'verified': False},
                   'powershell': {'encoded_command': False, 'script_evidence': evidence},
                   'provisional_scores': True}
        result['p1'] = derived  # Never trust supplied classification/priority labels.
        try:
            host = event.get('host', {})
            if host.get('os', {}).get('type') != 'windows' or not process_start(event):
                raise Unsupported('windows_process_start_required')
            key = (host.get('id'), process.get('entity_id'))
            if not all(isinstance(v, str) and v for v in key) or len(index.get(key, [])) != 1:
                raise Unsupported('missing_or_ambiguous_process_identity')
            if not isinstance(event.get('event', {}).get('id'), str) or not event['event']['id'].strip():
                raise Unsupported('source_event_id_missing')
            current, chain = event, [event]
            for hop in range(2):
                parent_id = current.get('process', {}).get('parent', {}).get('entity_id')
                if not isinstance(parent_id, str) or not parent_id:
                    raise Unsupported('parent_identity_missing')
                parents = index.get((host['id'], parent_id), [])
                if len(parents) != 1:
                    raise Unsupported('missing_or_ambiguous_parent')
                parent = parents[0]
                if parent_id in [e['process']['entity_id'] for e in chain]:
                    raise Unsupported('lineage_cycle')
                if not process_start(parent) or parent.get('host', {}).get('os', {}).get('type') != 'windows':
                    raise Unsupported('invalid_parent_event')
                parent_event_id = parent.get('event', {}).get('id')
                if not isinstance(parent_event_id, str) or not parent_event_id.strip():
                    raise Unsupported('parent_event_id_missing')
                if timestamp(parent) > timestamp(current):
                    raise Unsupported('invalid_process_order')
                reported = current['process'].get('parent', {}).get('name')
                actual = parent['process'].get('name', '').lower()
                if reported and (not isinstance(reported, str) or reported.lower() != actual):
                    raise Unsupported('parent_name_conflict')
                chain.append(parent)
                if actual in OFFICE:
                    break
                if hop == 0 and actual == 'cmd.exe':
                    current = parent
                    continue
                raise Unsupported('office_origin_not_established')
            else:
                raise Unsupported('office_origin_not_established')
            if len(chain) == 3 and (timestamp(event) - timestamp(chain[1])).total_seconds() > MAX_CMD_DELAY_SECONDS:
                raise Unsupported('cmd_delay_exceeded')
            derived['document_id'] = hashlib.sha256(json.dumps([host['id'], process['entity_id'], event['event']['id']]).encode()).hexdigest()
            derived['lineage'] = {'verified': True, 'office_origin': True,
                                  'path': 'office_powershell' if len(chain) == 2 else 'office_cmd_powershell'}
            derived['evidence'] = {'event_ids': [e['event']['id'] for e in reversed(chain)]}
            text = decode_command(process)
            derived['powershell']['encoded_command'] = True
            derived['powershell']['decoded_script'] = text
            evidence = analyze_script(text)
            evidence['source'] = 'encoded_command'
            derived['powershell']['script_evidence'] = evidence
            if evidence['status'] in {'download_only', 'download_and_execute'}:
                high = evidence['status'] == 'download_and_execute'
                derived['priority'] = {'severity': 'high' if high else 'medium', 'risk_score': 73 if high else 47}
        except Unsupported as error:
            evidence['reason'] = str(error)
        output.append(result)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='Local JSON array of synthetic process events')
    args = parser.parse_args()
    # Output may contain decoded script evidence. Use synthetic input only.
    events = json.loads(args.input.read_text())
    print(json.dumps({'original_events': events, 'prepared_events': prepare_events(events)}, indent=2))


if __name__ == '__main__':
    main()
