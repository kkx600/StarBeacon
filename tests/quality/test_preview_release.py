"""验证预览来源和包清单的拒绝边界；不作为真实产品验收。"""
import copy
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
import check_preview_release as preview

VERSION = "v0.1.0-rc.3"
COMMIT = "a" * 40
REPOSITORY = "kkx600/StarBeacon"
RUN_ID = "1234"


class PreviewReleaseTests(unittest.TestCase):
    def test_only_release_candidates_are_accepted(self):
        preview.validate_identity(VERSION, COMMIT, REPOSITORY, RUN_ID)
        for version in ("v0.1.0", "v0.1.0-beta.1", "v0.1.0-rc.0", "v00.1.0-rc.3", "../v0.1.0-rc.3", "v0.1.0-rc.3\n"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                preview.validate_identity(version, COMMIT, REPOSITORY, RUN_ID)
        for args in ((VERSION, "main", REPOSITORY, RUN_ID), (VERSION, COMMIT, "owner/repo/other", RUN_ID),
                     (VERSION, COMMIT, REPOSITORY, "12/34"), (VERSION, COMMIT, REPOSITORY, "0")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                preview.validate_identity(*args)

    def test_requires_exact_successful_main_push(self):
        run = {"id": int(RUN_ID), "head_sha": COMMIT, "head_branch": "main", "status": "completed", "conclusion": "success",
               "event": "push", "path": ".github/workflows/ci.yml", "head_repository": {"full_name": REPOSITORY}}
        preview.verify_run(run, COMMIT, REPOSITORY, RUN_ID)
        for key, value in (("id", 5678), ("head_sha", "b" * 40), ("head_branch", "codex/example"), ("status", "in_progress"),
                           ("conclusion", "failure"), ("event", "pull_request"), ("path", ".github/workflows/preview.yml"),
                           ("head_repository", {"full_name": "external/fork"}), ("head_repository", None)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                preview.verify_run({**run, key: value}, COMMIT, REPOSITORY, RUN_ID)

    def test_package_identity_set_and_verifier_failure(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = pathlib.Path(scratch)
            data = {"version": VERSION, "commit": COMMIT, "archives": [
                {"name": f"starbeacon-{bundle}-{VERSION}-linux-amd64.zip", "sha256": "b" * 64, "size": 1}
                for bundle in ("platform", "collector")]}
            for record in data["archives"]:
                (root / record["name"]).write_bytes(b"x")
            def save(value):
                (root / "checksums.json").write_text(json.dumps(value))
            save(data)
            with patch.object(preview, "verify_archive", side_effect=ValueError("实际归档拒绝")):
                with self.assertRaisesRegex(ValueError, "实际归档拒绝"):
                    preview.verify_packages(root, VERSION, COMMIT)
            for mutation in (lambda d: d.update(commit="c" * 40), lambda d: d.update(version="v0.1.0"),
                             lambda d: d["archives"].pop(), lambda d: d["archives"].__setitem__(1, d["archives"][0]),
                             lambda d: d["archives"][0].update(name="../../outside.zip"),
                             lambda d: d["archives"][0].update(size=True), lambda d: d["archives"][0].update(sha256="bad")):
                changed = copy.deepcopy(data)
                mutation(changed)
                save(changed)
                with self.subTest(data=changed), self.assertRaises(ValueError):
                    preview.verify_packages(root, VERSION, COMMIT)
            save(data)
            (root / "unexpected.zip").write_bytes(b"x")
            with self.assertRaises(ValueError):
                preview.verify_packages(root, VERSION, COMMIT)


if __name__ == "__main__":
    unittest.main()
