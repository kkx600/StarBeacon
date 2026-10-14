"""正式验收输入不能借用其他提交、分支、仓库或预览运行。"""
import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from check_evidence_source import verify_source


class EvidenceSourceTest(unittest.TestCase):
    def setUp(self):
        self.commit = "a" * 40
        self.run = {"id": 123, "head_sha": self.commit, "head_branch": "main", "status": "completed", "conclusion": "success", "event": "workflow_dispatch", "head_repository": {"full_name": "owned/project"}, "path": ".github/workflows/ci.yml"}
        self.artifacts = {"artifacts": [{"name": "starbeacon-acceptance-input", "expired": False, "workflow_run": {"id": 123, "head_sha": self.commit, "head_branch": "main"}}]}

    def verify(self, run=None, artifacts=None, run_id="123", commit=None):
        verify_source(self.run if run is None else run, self.artifacts if artifacts is None else artifacts, "owned/project", self.commit if commit is None else commit, run_id)

    def test_same_commit_main_origin_is_accepted(self):
        self.verify()

    def test_untrusted_or_unsuccessful_run_is_rejected(self):
        for key, value in {"id": 124, "head_sha": "b" * 40, "head_branch": "feature", "status": "in_progress", "conclusion": "failure", "event": "pull_request", "head_repository": {"full_name": "foreign/project"}, "path": ".github/workflows/preview.yml"}.items():
            run = copy.deepcopy(self.run); run[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(run=run)
        for value in ("0", "123/../", "1;false", "-1"):
            with self.subTest(id=value), self.assertRaises(ValueError):
                self.verify(run_id=value)
        with self.assertRaises(ValueError):
            self.verify(commit="main")

    def test_missing_expired_duplicate_or_wrong_source_artifact_is_rejected(self):
        mutations = [lambda a: a.clear(), lambda a: a.append(copy.deepcopy(a[0])), lambda a: a[0].update(expired=True), lambda a: a[0].update(name="starbeacon-frontend-evidence"), lambda a: a[0]["workflow_run"].update(head_sha="b" * 40), lambda a: a[0]["workflow_run"].update(id=124), lambda a: a[0]["workflow_run"].update(head_branch="feature")]
        for mutate in mutations:
            artifacts = copy.deepcopy(self.artifacts); mutate(artifacts["artifacts"])
            with self.assertRaises(ValueError):
                self.verify(artifacts=artifacts)
        with self.assertRaises(ValueError):
            self.verify(artifacts={})
