"""合成 Go 事件只验证完整执行与证据拒绝边界，不代表业务验收。"""
import json
import pathlib
import re
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests/acceptance"))
import integration_execution as execution


class IntegrationExecutionTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.names = [f"TestCase{i:03d}" for i in range(65)]
        self.omit = self.skip = self.duplicate = self.process_failure = False

    def execute(self, arguments, environment, name, timeout=600):
        events = []
        if name == "go-integration-inventory":
            events = [{"Action": "output", "Output": value + "\n"} for value in self.names]
        else:
            pattern = next(value[5:] for value in arguments if value.startswith("-run="))
            names = [value for value in self.names if re.fullmatch(pattern, value)]
            if self.omit: names = names[:-1]
            for value in names:
                events.extend([{"Action": "run", "Test": value}, {"Action": "skip" if self.skip else "pass", "Test": value}])
                if self.duplicate: events.append({"Action": "pass", "Test": value})
            (self.root / (name + ".cover")).write_text("mode: atomic\ngithub.com/kkx600/StarBeacon/internal/a.go:1.1,1.2 1 1\n")
        (self.root / (name + ".jsonl")).write_text("".join(json.dumps(row) + "\n" for row in events))
        return {"name": name, "status": "failed" if self.process_failure else "passed", "exit_code": 1 if self.process_failure else 0}

    def test_all_declared_tests_execute_once_and_coverage_uses_all_groups(self):
        result = execution.run(self.root, {}, self.execute)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["test_count"], 65)
        self.assertEqual(result["group_count"], 2)
        execution.verify(self.root, result)
        manifest = json.loads((self.root / "go-integration-manifest.json").read_text())
        names = [value for group in manifest["groups"] for value in group["tests"]]
        self.assertEqual(sorted(names), self.names)

    def test_missing_skipped_duplicate_or_failed_tests_cannot_pass(self):
        for flag in ("omit", "skip", "duplicate", "process_failure"):
            setattr(self, flag, True)
            (self.root / "go-integration.cover").write_text("old proof")
            result = execution.run(self.root, {}, self.execute)
            self.assertEqual(result["status"], "failed", flag)
            self.assertFalse((self.root / "go-integration.cover").exists(), flag)
            setattr(self, flag, False)

    def test_empty_or_duplicate_official_inventory_cannot_pass(self):
        for names in ([], ["TestSame", "TestSame"]):
            self.names = names
            self.assertEqual(execution.run(self.root, {}, self.execute)["status"], "failed")

    def test_changed_inventory_or_combined_coverage_cannot_be_reused(self):
        result = execution.run(self.root, {}, self.execute)
        profile = self.root / "go-integration.cover"
        lines = profile.read_text().splitlines()
        lines[-1] = lines[-1].rsplit(" ", 1)[0] + " 99"
        profile.write_text("\n".join(lines) + "\n")
        with self.assertRaises(ValueError): execution.verify(self.root, result)
        result = execution.run(self.root, {}, self.execute)
        path = self.root / "go-integration-inventory.jsonl"
        path.write_text(path.read_text() + json.dumps({"Action": "output", "Output": "TestAbsent\n"}) + "\n")
        with self.assertRaises(ValueError): execution.verify(self.root, result)

    def test_small_inventory_includes_examples_and_fuzz_seeds(self):
        self.names = ["Example", "FuzzCase", "Test"]
        result = execution.run(self.root, {}, self.execute)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["group_count"], 1)
        execution.verify(self.root, result)

    def test_only_known_go_instrumentation_warning_is_not_a_test_result(self):
        path = self.root / "inventory.jsonl"
        path.write_text(execution.INSTRUMENTATION_WARNING + "\n" + json.dumps({"Action": "output", "Output": "TestDeclared\n"}) + "\n")
        self.assertEqual(execution.inventory(path), ["TestDeclared"])
        path.write_text("unknown output\n" + path.read_text())
        with self.assertRaises(ValueError): execution.inventory(path)
