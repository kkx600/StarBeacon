"""只核对实际程序验收的写入前拒绝边界，不提供 Go 或 CA 功能证明。"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import accept_probe_pki_programs as programs


class ProbeProgramBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name).resolve()
        self.evidence = self.root / '.local/acceptance/programs'
        self.state = {'workspace_sha256': 'a' * 64, 'step_ca_image': 'sha256:' + 'b' * 64,
                      'host': 'fixture', 'directory': '/tmp/starbeacon-acceptance-sbacc_' + 'c' * 16}

    def test_foreign_existing_and_symlink_output_rejected_before_ssh(self):
        self.evidence.mkdir(parents=True)
        alias = self.root / '.local/acceptance/alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with patch.object(programs, 'ROOT', self.root), patch.object(programs.acceptance, 'read_state', return_value=self.state), patch.object(programs.acceptance, 'ssh') as ssh:
            for output in (self.root / 'foreign', self.evidence, alias / 'child', self.root / '.local/acceptance/../escape'):
                with self.subTest(path=str(output)), self.assertRaises(ValueError):
                    programs.run(pathlib.Path('fixture-state'), output)
            ssh.assert_not_called()

    def test_changed_source_or_absent_ca_cannot_create_remote_resources(self):
        for state, source in ((self.state, 'd' * 64), ({**self.state, 'step_ca_image': ''}, 'a' * 64)):
            with patch.object(programs, 'ROOT', self.root), patch.object(programs.acceptance, 'read_state', return_value=state), patch.object(programs.acceptance, 'snapshot_sources', return_value=({}, source)), patch.object(programs.acceptance, 'ssh') as ssh, self.assertRaises(ValueError):
                programs.run(pathlib.Path('fixture-state'), self.evidence)
            ssh.assert_not_called()
            self.assertFalse(self.evidence.exists())

    def test_failed_wrong_source_and_low_coverage_gate_cannot_create_fixture(self):
        for report in ({'status': 'failed'}, {'status': 'passed', 'workspace_sha256': 'd' * 64},
                       {'status': 'passed', 'workspace_sha256': 'a' * 64, 'coverage': {'percentage': 89.9}}):
            response = subprocess.CompletedProcess([], 0, stdout=json.dumps(report).encode())
            with patch.object(programs, 'ROOT', self.root), patch.object(programs.acceptance, 'read_state', return_value=self.state), patch.object(programs.acceptance, 'snapshot_sources', return_value=({}, 'a' * 64)), patch.object(programs.acceptance, 'verify_image'), patch.object(programs.acceptance, 'ssh', return_value=response) as ssh, self.assertRaises(ValueError):
                programs.run(pathlib.Path('fixture-state'), self.evidence)
            self.assertEqual(len(ssh.call_args_list), 1)
            self.assertEqual(ssh.call_args.args[1][0], 'cat')
            self.assertFalse(self.evidence.exists())


if __name__ == '__main__':
    unittest.main()
