"""Contract tests for real docs-only classification, never project/runtime tests."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import policy


class EventPolicyTests(unittest.TestCase):
    def test_only_narrow_documentation_is_light(self):
        for path in ['README.md', 'CONTRIBUTING.md', 'CHANGELOG.md', 'docs/guide.md', 'docs/FLAGSHIP-EVIDENCE.json']:
            with self.subTest(path=path):
                self.assertFalse(policy.native_required('push', 'refs/heads/main', [path]))
                self.assertFalse(policy.native_required('pull_request', 'refs/pull/7/merge', [path]))

    def test_source_license_provenance_ci_and_unknown_data_remain_native(self):
        for path in ['src/Core/Store.cs', 'Directory.Build.props', 'packages.lock.json', 'LICENSE', 'NOTICE.md', 'PROVENANCE.md', '.github/workflows/verify.yml', '.github/ci/policy.py', 'tools/integration.py', 'docs/fixture.json', '../README.md', 'docs/../src/core.cs', 'docs/a\\b.md', 'docs/a\nb.md']:
            with self.subTest(path=path):
                self.assertTrue(policy.native_required('push', 'refs/heads/main', ['README.md', path]))

    def test_all_tags_and_manual_runs_are_native_even_when_only_docs_changed(self):
        for event, ref in [('push', 'refs/tags/v0.1.0-preview.2'), ('push', 'refs/tags/csv-action-v1'), ('workflow_dispatch', 'refs/heads/main')]:
            with self.subTest(event=event, ref=ref):
                self.assertTrue(policy.native_required(event, ref, ['README.md']))

    def test_unknown_empty_large_or_unsupported_delta_is_native(self):
        for paths in [None, [], ['README.md'] * 5001]:
            self.assertTrue(policy.native_required('push', 'refs/heads/main', paths))
        self.assertTrue(policy.native_required('unknown', 'refs/heads/main', ['README.md']))

    def test_pr_uses_complete_merge_base_range_not_last_docs_commit(self):
        a, b, c = 'a' * 40, 'b' * 40, 'c' * 40
        payload = {'pull_request': {'base': {'sha': a}, 'head': {'sha': c}}}
        with patch.object(policy, 'git_output', side_effect=[a.encode(), b'README.md\0src/Core/Store.cs\0']) as run:
            changed = policy.changed_paths('pull_request', payload)
        self.assertEqual(('merge-base', a, c), run.call_args_list[0].args)
        self.assertEqual(('diff', '--no-renames', '--name-only', '-z', a, c, '--'), run.call_args_list[1].args)
        self.assertTrue(policy.native_required('pull_request', 'refs/pull/7/merge', changed))
        # A later docs-only main push is light only because main runs never share a cancelling/pending group.
        with patch.object(policy, 'git_output', return_value=b'README.md\0'):
            self.assertEqual(['README.md'], policy.changed_paths('push', {'before': b, 'after': c}))

    def test_git_failure_invalid_commit_and_invalid_utf8_cannot_be_docs(self):
        with patch.object(policy, 'git_output', side_effect=policy.PolicyError('failed')):
            self.assertIsNone(policy.changed_paths('push', {'before': 'a' * 40, 'after': 'b' * 40}))
        self.assertIsNone(policy.changed_paths('push', {'before': '0' * 40, 'after': 'b' * 40}))
        with patch.object(policy, 'git_output', return_value=b'docs/\xff.md\0'):
            self.assertIsNone(policy.changed_paths('push', {'before': 'a' * 40, 'after': 'b' * 40}))

    def test_real_markdown_checks_reject_unclosed_fence_and_missing_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('# Test\n\n[Missing](missing.md)\n', encoding='utf-8')
            with self.assertRaises(policy.PolicyError):
                policy.check_documents(['README.md'], root)
            (root / 'README.md').write_text('# Test\n\n```sh\ncommand\n', encoding='utf-8')
            with self.assertRaises(policy.PolicyError):
                policy.check_documents(['README.md'], root)
            (root / 'README.md').write_text('# Test\n\n[Folder](docs)\n', encoding='utf-8')
            (root / 'docs').mkdir()
            self.assertEqual(1, policy.check_documents(['README.md'], root)['checked'])

    def test_readme_deletion_and_bad_evidence_json_are_not_a_green_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(policy.PolicyError):
                policy.check_documents(['README.md'], root)
            (root / 'docs').mkdir()
            (root / 'docs/FLAGSHIP-EVIDENCE.json').write_text(json.dumps({'schema': 'wrong'}), encoding='utf-8')
            with self.assertRaises(policy.PolicyError):
                policy.check_documents(['docs/FLAGSHIP-EVIDENCE.json'], root)

    def test_light_gate_checks_exact_literal_source_inventory_without_importing_packager(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            (root / 'scripts/package.py').write_text('KEY="SIGNING-PUBLIC-KEY.pub"\nALLOWED=frozenset({"README.md",KEY})\nraise RuntimeError("MUST_NOT_EXECUTE")\n', encoding='utf-8')
            rows = b'100644 ' + b'a' * 40 + b' 0\tREADME.md\0' + b'100644 ' + b'b' * 40 + b' 0\tSIGNING-PUBLIC-KEY.pub\0'
            with patch.object(policy, 'git_output', return_value=rows):
                self.assertEqual(1, policy.check_source_inventory(root))
            with patch.object(policy, 'git_output', return_value=rows + b'100644 ' + b'c' * 40 + b' 0\tdocs/new-unallowlisted.md\0'):
                with self.assertRaises(policy.PolicyError):
                    policy.check_source_inventory(root)

    def test_light_source_inventory_rejects_symlink_modes_and_computed_allowlists(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            path = root / 'scripts/package.py'
            path.write_text('ALLOWED=frozenset({"README.md"})\n', encoding='utf-8')
            with patch.object(policy, 'git_output', return_value=b'120000 ' + b'a' * 40 + b' 0\tREADME.md\0'):
                with self.assertRaises(policy.PolicyError):
                    policy.check_source_inventory(root)
            path.write_text('ALLOWED=dynamic_inventory()\n', encoding='utf-8')
            with self.assertRaises(policy.PolicyError):
                policy.check_source_inventory(root)


if __name__ == '__main__':
    unittest.main(verbosity=2)
