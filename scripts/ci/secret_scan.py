"""Gitleaks wrapper: scan history or publishable files; print metadata only."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from validate import ROOT, files


def publishable_tree(destination):
    for source in files():
        if source.is_symlink() or not source.is_file():
            raise ValueError('Symlink/non-file cannot enter secret-scan tree')
        target = destination/source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def scan(binary, mode):
    with tempfile.TemporaryDirectory(prefix='p1-secret-scan-') as folder:
        folder = Path(folder)
        target = ROOT
        if mode == 'dir':
            target = folder/'publishable'
            target.mkdir()
            publishable_tree(target)
        report = folder/'redacted-report.json'
        # Only Git history uses reviewed, commit-specific false-positive fingerprints.
        # Current publishable content gets an explicitly empty ignore policy.
        ignore = ROOT/'.gitleaksignore'
        if mode == 'dir':
            ignore = folder/'empty.gitleaksignore'
            ignore.write_text('')
        result = subprocess.run([binary, mode, '--config', str(ROOT/'.gitleaks.toml'),
                                 '--gitleaks-ignore-path', str(ignore),
                                 '--redact', '--no-banner', '--report-format', 'json',
                                 '--report-path', str(report), str(target)],
                                capture_output=True, text=True)
        if result.returncode == 0:
            print('PASS | Gitleaks ' + mode + ' scan')
            return 0
        if result.returncode == 1 and report.exists():
            findings = json.loads(report.read_text())
            print('FAIL | Secret-exposure findings: ' + str(len(findings)))
            for finding in findings:
                # Never print Match, Secret, line content, fingerprints or raw scanner output.
                path = Path(finding['File'])
                if path.is_absolute():
                    path = path.relative_to(target)
                print(json.dumps({'file': str(path), 'line': finding['StartLine'], 'rule': finding['RuleID']}))
            return 1
        print('FAIL | Gitleaks could not complete; raw diagnostics suppressed')
        return 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gitleaks-bin', required=True)
    parser.add_argument('--mode', choices=('git', 'dir'), default='dir')
    args = parser.parse_args()
    try:
        raise SystemExit(scan(args.gitleaks_bin, args.mode))
    except (OSError, ValueError, KeyError):
        raise SystemExit('FAIL | Secret scan failed; sensitive details suppressed') from None
