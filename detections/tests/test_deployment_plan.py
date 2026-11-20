"""Offline deployment-plan regression tests."""

import hashlib
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from detections.processing import deployment_plan as planner


class DeploymentPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.commit = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=planner.ROOT, text=True,
        ).strip()
        cls.artifacts = planner.committed_artifacts(cls.commit)

    def test_plan_is_reproducible_and_binds_git_blobs(self):
        plan = planner.build_plan(self.commit)
        self.assertEqual(plan, planner.build_plan(self.commit))
        self.assertEqual(plan['commit'], self.commit)
        self.assertEqual(plan['mode'], 'offline')
        self.assertIs(plan['payload']['enabled'], False)
        self.assertEqual(plan['payload']['actions'], [])
        for path, digest in plan['artifact_sha256'].items():
            self.assertEqual(digest, hashlib.sha256(self.artifacts[path]).hexdigest())
        self.assertEqual(planner.verify_plan(self.commit, plan), plan['plan_sha256'])

    def test_modified_plan_is_rejected_even_after_rehashing(self):
        for change in ('enabled', 'blob hash', 'commit'):
            with self.subTest(change=change):
                plan = planner.build_plan(self.commit)
                if change == 'enabled':
                    plan['payload']['enabled'] = True
                    plan['payload_sha256'] = planner.sha256(planner.canonical(plan['payload']))
                elif change == 'blob hash':
                    plan['artifact_sha256'][planner.ARTIFACTS[0]] = '0' * 64
                else:
                    plan['commit'] = '0' * 40
                del plan['plan_sha256']
                plan['plan_sha256'] = planner.sha256(planner.canonical(plan))
                with self.assertRaisesRegex(ValueError, 'Plan differs'):
                    planner.verify_plan(self.commit, plan)

    def test_invalid_committed_artifact_combinations_are_rejected(self):
        rule_path, query_path, _ = planner.ARTIFACTS
        mutations = [
            (query_path, self.artifacts[query_path] + b'\n| LIMIT 1\n'),
            (rule_path, self.artifacts[rule_path].replace(b'enabled: false', b'enabled: true')),
            (rule_path, self.artifacts[rule_path] + b'\nenabled: false\n'),
            (rule_path, self.artifacts[rule_path] + b'\nexceptions_list: []\n'),
        ]
        for path, data in mutations:
            with self.subTest(path=path, tail=data[-22:]):
                with patch.object(planner, 'committed_artifacts',
                                  return_value={**self.artifacts, path: data}):
                    with self.assertRaises(ValueError):
                        planner.build_plan(self.commit)

    def test_commit_must_be_a_full_available_commit_sha(self):
        blob_sha = subprocess.check_output(
            ['git', 'rev-parse', f'{self.commit}:{planner.ARTIFACTS[0]}'],
            cwd=planner.ROOT, text=True,
        ).strip()
        for commit in ('HEAD', self.commit[:12], blob_sha, '0' * 40):
            with self.subTest(commit=commit), self.assertRaises(ValueError):
                planner.build_plan(commit)

    def test_missing_artifact_fails_closed(self):
        with patch.object(planner, 'ARTIFACTS', ('missing.yml',)):
            with self.assertRaisesRegex(ValueError, 'unavailable locally'):
                planner.build_plan(self.commit)

    def test_git_reads_blobs_instead_of_opening_worktree_artifacts(self):
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('worktree read')):
            self.assertEqual(planner.committed_artifacts(self.commit), self.artifacts)
