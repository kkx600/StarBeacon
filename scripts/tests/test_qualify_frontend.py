"""工程验收拒绝跳过、陈旧源码、不完整覆盖与历史目录复用。"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import qualify_frontend as frontend


class FrontendQualificationTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name).resolve()
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        (self.root / ".gitignore").write_text(".local/\n")
        self.source = self.root / "web/platform/src/app.ts"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("export {}")
        (self.root / "web/scripts").mkdir()
        (self.root / "web/scripts/tool.test.mjs").write_text("// 工具测试夹具")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], cwd=self.root, check=True)
        self.output = self.root / ".local/acceptance/web"
        self.pending = False
        self.covered = 1
        self.fail = False
        self.change = False
        self.actual_run = subprocess.run

    def run_step(self, command, **options):
        if command[0] == "git":
            return self.actual_run(command, **options)
        log = options["stdout"]
        if "--test-reporter=tap" in command:
            log.write(b"# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n")
        if "--coverage" in command:
            tests = {"success": True, "numPassedTests": 1, "numFailedTests": 0, "numPendingTests": int(self.pending), "numTodoTests": 0, "numTotalTests": 1, "testResults": [{}]}
            (self.output / "tests.json").write_text(json.dumps(tests))
            coverage = {k: {"total": 1, "covered": self.covered, "skipped": 0} for k in ("statements", "branches", "functions", "lines")}
            (self.output / "coverage").mkdir()
            (self.output / "coverage/coverage-summary.json").write_text(json.dumps({"total": coverage, str(self.source): coverage}))
        if self.change:
            self.source.write_text("changed during execution")
        return subprocess.CompletedProcess(command, 1 if self.fail else 0)

    def qualify(self):
        with patch.object(frontend.subprocess, "run", side_effect=self.run_step):
            return frontend.qualify(self.output, self.root)

    def test_success_freezes_manifest_counts_and_all_evidence(self):
        report = self.qualify()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["tool_tests"], 1)
        self.assertEqual(len(report["steps"]), 4)
        self.assertEqual(report["coverage"]["branches"], 100)
        from source_snapshot import verify
        verify(self.root, json.loads((self.output / "source.json").read_text()))
        self.assertIn("source.json", {row["path"] for row in report["evidence"]})
        with self.assertRaises(FileExistsError):
            self.qualify()

    def test_pending_tests_cannot_qualify(self):
        self.pending = True
        self.assertEqual(self.qualify()["status"], "failed")

    def test_low_coverage_cannot_qualify(self):
        self.covered = 0
        self.assertEqual(self.qualify()["status"], "failed")

    def test_source_change_stops_before_following_steps(self):
        self.change = True
        report = self.qualify()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(report["steps"]), 1)

    def test_actual_failed_process_is_not_overridden_by_old_report(self):
        self.fail = True
        report = self.qualify()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["steps"][0]["exit_code"], 1)

    def test_traversal_and_external_output_are_rejected(self):
        for directory in (self.root / "output", self.root / ".local/acceptance/../escape"):
            with self.assertRaises(ValueError):
                frontend.qualify(directory, self.root)
            self.assertFalse(directory.exists())
