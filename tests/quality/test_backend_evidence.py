"""合成证据仅验证验收门禁的拒绝边界，不代表产品功能通过。"""
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/acceptance"))
sys.path.insert(0, str(ROOT / "scripts"))
import combine_backend
import remote_acceptance


class BackendEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.directory = pathlib.Path(self.scratch.name)
        (self.directory / "capture").mkdir()
        self.source = {"commit": "a" * 40, "workspace_sha256": "b" * 64, "project": "sbacc_" + "c" * 16, "clean_commit": False}
        self.baseline = {"schema_version": 1, **self.source, "environment": "remote_docker", "status": "passed", "results": [{"name": name, "status": "passed", "exit_code": 0} for name in ("migrate", "runtime-role", "go-unit", "go-integration", "go-cli-format", "pcap-inspection-benchmark")], "evidence": []}
        self.capture = {"schema_version": 1, **self.source, "environment": "remote_docker", "status": "passed", "scope": "managed_af_packet_live_http_to_search_and_notification", "exit_code": 0, "evidence": []}
        for name in ("go-unit.jsonl", "go-integration.jsonl", "go-unit.cover", "go-integration.cover", "go-cli.cover"):
            body = json.dumps({"Action": "pass", "Test": "TestFixture"}) + "\n" if name.endswith(".jsonl") else "fixture-only\n"
            self.evidence(self.baseline, self.directory, name, body)
        self.evidence(self.capture, self.directory / "capture", "go-capture.jsonl", json.dumps({"Action": "pass", "Test": "TestManagedCaptureNativeLiveHTTPEndToEnd"}) + "\n")
        self.evidence(self.capture, self.directory / "capture", "go-capture.cover", "fixture-only\n")

    def evidence(self, report, root, name, body):
        path = root / name
        path.write_text(body)
        report["evidence"] = [row for row in report["evidence"] if row["path"] != name]
        report["evidence"].append({"path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})

    def verify(self):
        combine_backend.verify_execution(self.source, self.baseline, self.capture, self.directory)

    def test_matching_fixture_is_accepted(self):
        self.verify()

    def test_stale_or_failed_capture_cannot_be_combined(self):
        for key, value in (("workspace_sha256", "d" * 64), ("commit", "e" * 40), ("project", "sbacc_" + "f" * 16), ("status", "failed"), ("clean_commit", 0), ("schema_version", True), ("exit_code", False), ("scope", "offline_only")):
            with self.subTest(key=key):
                original = copy.deepcopy(self.capture)
                self.capture[key] = value
                with self.assertRaises(ValueError):
                    self.verify()
                self.capture = original

    def test_missing_or_malformed_phase_is_rejected(self):
        original = copy.deepcopy(self.baseline)
        for rows in ([], [None] * 6, [{"name": [], "status": "passed", "exit_code": 0}] * 6, [original["results"][0]] * 6):
            with self.subTest(rows=rows):
                self.baseline["results"] = rows
                with self.assertRaises(ValueError):
                    self.verify()
        self.baseline = original
        self.baseline["results"][0]["exit_code"] = False
        with self.assertRaises(ValueError):
            self.verify()

    def test_modified_missing_or_escaping_evidence_is_rejected(self):
        for evidence in ([], [{"path": "../go-capture.jsonl", "sha256": "b" * 64}], [{"path": ".", "sha256": "b" * 64}], [*self.capture["evidence"], self.capture["evidence"][0]]):
            with self.subTest(evidence=evidence):
                report = copy.deepcopy(self.capture)
                report["evidence"] = evidence
                with self.assertRaises(ValueError):
                    combine_backend.verify_execution(self.source, self.baseline, report, self.directory)
        (self.directory / "capture/go-capture.cover").write_text("changed")
        with self.assertRaises(ValueError):
            self.verify()

    def test_hashed_failure_skip_or_empty_log_is_rejected(self):
        for action in ("fail", "skip", "output"):
            for name in ("go-unit.jsonl", "go-integration.jsonl"):
                with self.subTest(action=action, name=name):
                    self.evidence(self.baseline, self.directory, name, json.dumps({"Action": action, "Test": "TestFixture"}) + "\n")
                    with self.assertRaises(ValueError):
                        self.verify()
                    self.evidence(self.baseline, self.directory, name, json.dumps({"Action": "pass", "Test": "TestFixture"}) + "\n")
        self.evidence(self.capture, self.directory / "capture", "go-capture.jsonl", json.dumps({"Action": "pass", "Test": "TestOther"}) + "\n")
        with self.assertRaises(ValueError):
            self.verify()

    def test_package_without_compiled_tests_requires_official_identity_and_output(self):
        package = "github.com/kkx600/StarBeacon/internal/buildinfo"
        passed = {"Action": "pass", "Test": "TestFixture"}
        output = {"Action": "output", "Package": package, "Output": "?   \t" + package + "\t[no test files]\n"}
        skipped = {"Action": "skip", "Package": package}
        body = lambda rows: "".join(json.dumps(row) + "\n" for row in rows)
        for rows, allowed, valid in (([passed, output, skipped], {package}, True), ([passed, skipped], {package}, False), ([passed, output, skipped], set(), False), ([passed, dict(output, Package="other"), skipped], {package}, False), ([passed, output, dict(skipped, Test="TestSkipped")], {package}, False), ([passed, output, skipped, skipped], {package}, False)):
            with self.subTest(rows=rows, allowed=allowed):
                self.evidence(self.baseline, self.directory, "go-unit.jsonl", body(rows))
                with patch.object(combine_backend, "packages_without_tests", return_value=allowed) as inventory:
                    if valid:
                        self.verify()
                        inventory.assert_called_once_with(pathlib.Path("/source"))
                    else:
                        with self.assertRaises(ValueError):
                            self.verify()
        self.evidence(self.baseline, self.directory, "go-unit.jsonl", body([passed, output, skipped]))
        with patch.object(combine_backend, "packages_without_tests", side_effect=ValueError("Go 清单不可用")), self.assertRaises(ValueError):
            self.verify()

    def test_symbolic_link_evidence_is_rejected(self):
        path = self.directory / "capture/go-capture.cover"
        path.unlink()
        path.symlink_to(self.directory / "go-unit.cover")
        with self.assertRaises(ValueError):
            self.verify()


class BackendRunnerTests(unittest.TestCase):
    state = {"host": "fixture_host", "directory": "/tmp/starbeacon-acceptance-sbacc_" + "a" * 16}

    def test_fixture_start_failure_always_reclaims_owned_container_volumes(self):
        calls = []

        def compose(state, args, **options):
            calls.append(args)
            if args[0] == "ps":
                return subprocess.CompletedProcess(args, 0, stdout=b"")
            if args[:2] == ["up", "-d"]:
                raise subprocess.TimeoutExpired(args, 60)
            return subprocess.CompletedProcess(args, 0)

        with patch.object(remote_acceptance, "compose", side_effect=compose), patch.object(remote_acceptance, "ssh"), self.assertRaises(subprocess.TimeoutExpired):
            remote_acceptance.run_backend(self.state)
        self.assertIn(["stop", "capture-fixture"], calls)
        self.assertIn(["rm", "-f", "-v", "capture-fixture"], calls)
        self.assertFalse(any("capture-runner" in row and row[0] == "run" for row in calls))

    def test_running_executor_blocks_mutations(self):
        with patch.object(remote_acceptance, "compose", return_value=subprocess.CompletedProcess([], 0, stdout=b"running\n")), patch.object(remote_acceptance, "ssh") as ssh, self.assertRaises(ValueError):
            remote_acceptance.run_backend(self.state)
        ssh.assert_not_called()

    def test_backend_failure_does_not_start_capture_or_combine_reports(self):
        calls = []

        def compose(state, args, **options):
            calls.append(args)
            if args[0] == "ps":
                return subprocess.CompletedProcess(args, 0, stdout=b"")
            raise subprocess.CalledProcessError(1, args)

        with patch.object(remote_acceptance, "compose", side_effect=compose), patch.object(remote_acceptance, "ssh"), self.assertRaises(subprocess.CalledProcessError):
            remote_acceptance.run_backend(self.state)
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
