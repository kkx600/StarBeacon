"""远程执行超时也必须留下失败报告，不推定通过或伪造退出码。"""
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("acceptance_baseline_timeout", ROOT / "tests/acceptance/baseline.py")
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


class BaselineTimeoutTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.root_patch = patch.object(baseline, "ROOT", self.root)
        self.reports_patch = patch.object(baseline, "REPORTS", self.root)
        self.root_patch.start(); self.reports_patch.start()
        self.addCleanup(self.root_patch.stop); self.addCleanup(self.reports_patch.stop)

    def test_actual_deadline_preserves_log_without_invented_exit_code(self):
        result = baseline.execute([sys.executable, "-u", "-c", "import time; print('started'); time.sleep(10)"], dict(os.environ), "deadline", timeout=0.8)
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["exit_code"])
        self.assertIs(result["timed_out"], True)
        self.assertTrue((self.root / "deadline.jsonl").is_file())

    def test_nonzero_exit_is_preserved(self):
        result = baseline.execute([sys.executable, "-c", "raise SystemExit(3)"], dict(os.environ), "failed")
        self.assertEqual(result["exit_code"], 3)
        self.assertEqual(result["status"], "failed")

    def test_failed_unit_does_not_start_integration_and_keeps_final_report(self):
        self.check_report("go-unit", expected=3)

    def test_integration_deadline_keeps_final_report(self):
        self.check_report("go-integration", expected=4)

    def check_report(self, failure, expected):
        (self.root / "source.json").write_text(json.dumps({"commit": "a" * 40, "workspace_sha256": "b" * 64, "clean_commit": False}))
        def execute(arguments, environment, name, timeout=600):
            return {"name": name, "status": "failed" if name == failure else "passed", "exit_code": None if name == failure else 0, "timed_out": name == failure}
        values = {key: "fixture" for key in ("POSTGRES_PASSWORD", "SB_RUNTIME_DB_PASSWORD", "REDIS_PASSWORD", "NATS_TOKEN", "SB_ACCEPTANCE_PROJECT")}
        with patch.dict(os.environ, values), patch.object(baseline, "execute", side_effect=execute) as run, patch.object(baseline.integration_execution, "run", side_effect=lambda directory, environment, runner: runner([], environment, "go-integration", timeout=1260)), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(baseline.main(), 1)
        report = json.loads((self.root / "baseline.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(report["results"]), expected)
        self.assertEqual(report["results"][-1]["name"], failure)
        self.assertTrue(report["results"][-1]["timed_out"])
        self.assertEqual(run.call_count, expected)
