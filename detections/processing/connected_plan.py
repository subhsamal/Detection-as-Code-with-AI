"""Compare committed P1-PS-001 artifacts with an existing Kibana rule over HTTPS."""

import argparse
import base64
import getpass
from http.client import HTTPException, HTTPSConnection
import json
import re
import ssl
import subprocess
import sys
from urllib.parse import urlsplit
from uuid import UUID
import warnings

from detections.processing.deployment_plan import RULE_ID, build_plan, canonical
from detections.processing.deployment_state import read_rule
from detections.processing.kibana_rule_reader import KibanaRuleReader, rule_path
from scripts.ci.validate import ValidationError, require

MAX_RESPONSE_BYTES = 1024 * 1024


class _KibanaHTTPSConnection:
    response_limit = MAX_RESPONSE_BYTES

    def __init__(self, origin, ca_file):
        url = urlsplit(origin)
        require(url.scheme == 'https' and
                re.fullmatch(r'(?:127\.0\.0\.1|\[::1\]):[0-9]{1,5}', url.netloc) and
                0 < url.port <= 65535 and origin == f'https://{url.netloc}',
                'Use an HTTPS origin with a loopback IP and explicit port')
        self.origin = origin
        self.host = url.hostname
        self.port = url.port
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_verify_locations(cafile=ca_file)

    def _request(self, method, path, username, password, payload=None):
        require(bool(username and password) and ':' not in username, 'Invalid Basic credentials')
        encoded = base64.b64encode(f'{username}:{password}'.encode()).decode('ascii')
        connection = HTTPSConnection(self.host, self.port, context=self.context, timeout=10)
        try:
            headers = {'Accept': 'application/json', 'Authorization': f'Basic {encoded}'}
            if payload is None:
                connection.request(method, path, headers=headers)
            else:
                headers.update({'Content-Type': 'application/json', 'kbn-xsrf': 'day4-canary'})
                connection.request(method, path, body=canonical(payload), headers=headers)
            response = connection.getresponse()
            status = response.status
            if status in (401, 403, 404):
                raise ValidationError(f'Kibana rule request blocked by HTTP {status}')
            require(status == 200, 'Unsupported Kibana HTTP response')
            require(response.headers.get_content_type() == 'application/json',
                    'Unsupported Kibana response media type')
            limit = self.response_limit
            body = response.read(limit + 1)
            require(len(body) <= limit, 'Kibana response exceeds size limit')
            return status, body.decode('utf-8')
        except ssl.SSLCertVerificationError:
            raise ValidationError('Kibana TLS certificate or hostname verification failed') from None
        except ssl.SSLError:
            raise ValidationError('Kibana TLS handshake failed') from None
        except TimeoutError:
            raise ValidationError('Kibana HTTPS request timed out') from None
        except (OSError, HTTPException):
            raise ValidationError('Kibana HTTPS request failed') from None
        finally:
            connection.close()



class KibanaHTTPS(_KibanaHTTPSConnection):
    def __init__(self, origin, space, ca_file):
        self.path = rule_path(space)
        super().__init__(origin, ca_file)

    def read(self, path, username, password):
        require(path == self.path, 'Unsupported Kibana read path')
        return self._request('GET', self.path, username, password)

def compare(artifact, store, expected_uuid):
    observed = read_rule(store)
    require(observed is not None and observed['id'] == expected_uuid,
            'Observed rule UUID differs from the expected rule')
    desired = artifact['payload']
    actual = observed['payload']
    require(all(type(actual[field]) is type(desired[field]) for field in actual.keys() & desired.keys()),
            'Malformed managed rule field type')
    drift = [field for field in sorted(actual.keys() | desired.keys())
             if field not in actual or field not in desired or
             canonical(actual[field]) != canonical(desired[field])]
    return {
        'result': 'DRIFT' if drift else 'NOOP',
        'commit': artifact['commit'],
        'artifact_plan_sha256': artifact['plan_sha256'],
        'target': store.target,
        'rule_id': RULE_ID,
        'uuid': expected_uuid,
        'revision': observed['revision'],
        'drift_fields': drift,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('commit', 'origin', 'space', 'ca-file', 'expected-uuid'):
        parser.add_argument(f'--{option}', required=True)
    args = parser.parse_args(argv)
    try:
        artifact = build_plan(args.commit)
        require(str(UUID(args.expected_uuid)) == args.expected_uuid, 'Expected a canonical UUID')
        transport = KibanaHTTPS(args.origin, args.space, args.ca_file)
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            username = getpass.getpass('Kibana deployment username: ')
            password = getpass.getpass('Kibana deployment password: ')
        reader = KibanaRuleReader(transport.origin, args.space,
                                  lambda path: transport.read(path, username, password))
        report = compare(artifact, reader, args.expected_uuid)
    except ValidationError as error:
        print(f'BLOCKED: {error}', file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError, KeyError, TypeError, AttributeError,
            IndexError, EOFError, getpass.GetPassWarning, RecursionError):
        print('BLOCKED: Invalid input, unavailable secure prompt/CA, or malformed response',
              file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 2 if report['drift_fields'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
