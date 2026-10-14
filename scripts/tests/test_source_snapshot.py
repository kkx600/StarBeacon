"""源码证据必须识别内容、配置、目录和未提交文件的变化。"""
import copy
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from source_snapshot import snapshot, verify


class SourceSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        (self.root / ".gitignore").write_text(".local/\nweb/node_modules/\nweb/platform/dist/\n")
        (self.root / "web/platform/src").mkdir(parents=True)
        (self.root / "web/platform/src/app.ts").write_text("export const app = '星烽'\n")
        (self.root / "web/package.json").write_text('{"name":"fixture"}\n')

    def test_reproducible_across_locations_and_build_outputs(self):
        original = snapshot(self.root)
        with tempfile.TemporaryDirectory() as directory:
            other = pathlib.Path(directory)
            subprocess.run(["git", "init", "--quiet", directory], check=True)
            for row in original["files"]:
                p = other / row["path"]
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes((self.root / row["path"]).read_bytes())
            self.assertEqual(original, snapshot(other))
        (self.root / "web/platform/dist").mkdir()
        (self.root / "web/platform/dist/app.js").write_text("build")
        verify(self.root, original)
        self.assertEqual([r["path"] for r in original["files"]], ["web/package.json", "web/platform/src/app.ts"])

    def test_source_config_and_untracked_addition_invalidate_evidence(self):
        for name in ("web/platform/src/app.ts", "web/package.json", "web/pnpm-workspace.yaml", "web/tests/pending.test.ts"):
            original = snapshot(self.root)
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("changed")
            with self.assertRaisesRegex(ValueError, "快照不一致"):
                verify(self.root, original)

    def test_tracked_deletion_and_tampered_manifest_are_detected(self):
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        original = snapshot(self.root)
        altered = copy.deepcopy(original)
        altered["files"][0]["size"] += 1
        with self.assertRaises(ValueError):
            verify(self.root, altered)
        (self.root / "web/package.json").unlink()
        with self.assertRaises(ValueError):
            verify(self.root, original)
        self.assertEqual(len(snapshot(self.root)["files"]), 1)

    def test_ignored_build_input_is_still_part_of_the_snapshot(self):
        (self.root / ".gitignore").write_text("web/platform/src/private.ts\nweb/platform/vite.config.ts\n")
        original = snapshot(self.root)
        (self.root / "web/platform/src/private.ts").write_text("export default 42")
        with self.assertRaises(ValueError):
            verify(self.root, original)
        original = snapshot(self.root)
        (self.root / "web/platform/vite.config.ts").write_text("export default {}")
        with self.assertRaises(ValueError):
            verify(self.root, original)

    def test_symlinks_and_invalid_scope_are_rejected(self):
        with self.assertRaises(ValueError):
            snapshot(self.root, "../")
        (self.root / "web/platform/src/link.ts").symlink_to("app.ts")
        with self.assertRaisesRegex(ValueError, "符号链接"):
            snapshot(self.root)
        (self.root / "web/platform/src/link.ts").unlink()
        (self.root / "outside").mkdir()
        (self.root / "web/tests").symlink_to(self.root / "outside", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "符号链接"):
            snapshot(self.root)
