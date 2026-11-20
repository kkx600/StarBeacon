import datetime
import importlib.util
import hashlib
import io
import json
import os
import pathlib
import subprocess
import tempfile
import time
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "cleanup_acceptance.py"
SPEC = importlib.util.spec_from_file_location("cleanup_acceptance", SCRIPT)
cleanup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cleanup)


class LocalCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.directory = self.root / ".local/acceptance"
        self.directory.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", self.root], check=True, capture_output=True)
        self.now = time.time()

    def file(self, name, value="验收记录", *, recent=False):
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        stamp = self.now if recent else self.now - 72 * 3600
        os.utime(path, (stamp, stamp))
        if not recent:
            for parent in path.parents:
                if parent == self.directory:
                    break
                os.utime(parent, (stamp, stamp))
        return path

    def plan(self, **kwargs):
        return cleanup.local_plan(self.root, current="v0.5.1", now=self.now, **kwargs)

    def test_semantic_version_predecessor_is_not_string_sort(self):
        values = ["v0.5.0", "v0.4.9", "v0.5.2", "v0.5.1", "v0.5.1-rc.10", "v0.5.1-rc.2"]
        self.assertEqual(cleanup.previous_versions(values, "v0.5.1"), ["v0.5.1", "v0.5.0"])
        self.assertEqual(cleanup.previous_versions(values, "v0.5.1-rc.10"), ["v0.5.1-rc.10", "v0.5.1-rc.2"])
        self.assertEqual(cleanup.previous_versions(["v0.5.0", "v0.4.9"], "v0.5.1"), ["v0.5.1", "v0.5.0"])
        for bad in ["../0.5.1", "0.5", "v01.5.1", "v0.5.1-rc.01", "v0.5.1-rc..1"]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                cleanup.version_key(bad)

    def test_release_keeps_current_and_one_previous_without_duplicate_candidates(self):
        for version, directory in [("v0.5.1", "current"), ("v0.5.0", "previous"), ("v0.4.9", "old"), ("v0.5.0", "duplicate")]:
            manifest = {"version": version, "archives": [{"name": "platform.zip"}, {"name": "collector.zip"}]}
            self.file(directory + "/checksums.json", json.dumps(manifest), recent=True)
            self.file(directory + "/platform.zip", "platform", recent=True)
        os.utime(self.directory / "previous/checksums.json", (self.now + 1, self.now + 1))
        plan = self.plan()
        self.assertEqual(plan["retained_versions"], ["v0.5.1", "v0.5.0"])
        self.assertEqual(set(plan["retained_package_directories"]), {"current", "previous"})
        deleted = {p["path"] for p in plan["files"]}
        self.assertIn("old/platform.zip", deleted)
        self.assertIn("duplicate/platform.zip", deleted)
        self.assertNotIn("previous/platform.zip", deleted)

    def test_complete_previous_bundle_beats_newer_incomplete_duplicate(self):
        records = []
        for name in ["platform.zip", "collector.zip"]:
            self.file("complete/" + name, name)
            records.append({"name": name, "size": len(name), "sha256": hashlib.sha256(name.encode()).hexdigest()})
        value = json.dumps({"version": "v0.5.0", "archives": records})
        self.file("complete/checksums.json", value)
        self.file("incomplete/checksums.json", value, recent=True)
        self.assertEqual(self.plan()["retained_package_directories"], ["complete"])

    def test_optional_v_prefix_does_not_delete_current_release(self):
        self.file("current/checksums.json", json.dumps({"version": "v0.5.1", "archives": [{"name": "a.zip"}, {"name": "b.zip"}]}))
        self.file("current/a.zip")
        plan = cleanup.local_plan(self.root, current="0.5.1", now=self.now)
        self.assertEqual(plan["retained_package_directories"], ["current"])
        self.assertEqual(plan["files"], [])

    def test_future_release_candidate_is_not_deleted_as_old_content(self):
        value = json.dumps({"version": "v0.6.0", "archives": [{"name": "a.zip"}, {"name": "b.zip"}]})
        self.file("future/checksums.json", value)
        self.file("future/a.zip")
        self.assertEqual(self.plan()["files"], [])

    def test_protects_state_credentials_recent_files_and_explicit_run(self):
        state = {"host": "home_dev", "project": "sbacc_1234567890abcdef", "directory": "/owned"}
        self.file("remote.json", json.dumps(state))
        self.file("some/pki/ca.key")
        self.file("some/data/device.bolt")
        self.file("secret.env")
        self.file("current/run.log", recent=True)
        self.file("explicit/run.log")
        self.file("old/run.log")
        plan = self.plan(keep=[".local/acceptance/explicit"])
        self.assertEqual([p["path"] for p in plan["files"]], ["old/run.log"])

    def test_tracked_file_never_removed(self):
        path = self.file("tracked.log")
        subprocess.run(["git", "-C", self.root, "add", "--", str(path)], check=True, capture_output=True)
        self.assertEqual(self.plan()["files"], [])

    def test_only_two_distinct_completed_sources_retained(self):
        for number in range(3):
            path = self.file(f"run{number}-backend.json", json.dumps({"status": "passed", "workspace_sha256": str(number) * 64}))
            os.utime(path, (self.now - (72 - number) * 3600,) * 2)
            self.file(f"run{number}-run.log")
        plan = self.plan()
        self.assertEqual(set(plan["retained_report_sets"]), {"run1-backend.json", "run2-backend.json"})
        self.assertEqual({p["path"] for p in plan["files"]}, {"run0-backend.json", "run0-run.log"})

    def test_flat_summary_keeps_one_complete_raw_directory_for_same_source(self):
        value = json.dumps({"status": "passed", "workspace_sha256": "1" * 64})
        self.file("current-backend.json", value, recent=True)
        self.file("raw/reports/backend.json", value)
        self.file("raw/reports/unit.cover", "coverage")
        self.assertEqual(self.plan()["files"], [])

    def test_plan_does_not_delete_and_changed_file_is_skipped(self):
        path = self.file("old.log", "原记录")
        plan = self.plan()
        self.assertTrue(path.exists())
        path.write_text("新的运行内容")
        result = cleanup.apply_files(plan)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["deleted_files"], 0)
        self.assertEqual(path.read_text(), "新的运行内容")

    def test_recent_extract_directory_protects_members_with_old_timestamps(self):
        path = self.file(".report-staging-current/reports/unit.cover", "coverage")
        os.utime(self.directory / ".report-staging-current", (self.now, self.now))
        self.assertEqual(self.plan()["files"], [])

    def test_empty_active_and_identity_directories_are_not_removed(self):
        active = self.directory / "current-run"
        active.mkdir()
        identity = self.directory / "data"
        identity.mkdir()
        os.utime(identity, (self.now - 72 * 3600,) * 2)
        cleanup.apply_files(self.plan())
        self.assertTrue(active.is_dir())
        self.assertTrue(identity.is_dir())

    def test_checkout_without_tags_protects_unidentified_release_versions(self):
        self.file("package/checksums.json", json.dumps({"version": "v0.5.1", "archives": [{"name": "a.zip"}, {"name": "b.zip"}]}))
        self.file("package/a.zip")
        self.file("old.log")
        plan = cleanup.local_plan(self.root, now=self.now)
        self.assertIsNone(plan["current_version"])
        self.assertEqual([r["path"] for r in plan["files"]], ["old.log"])

    def test_symlink_root_and_parent_cannot_escape(self):
        external = self.root / "outside"
        external.mkdir()
        path = self.file("branch/record.log")
        plan = self.plan()
        (self.directory / "branch").rename(external / "branch")
        (self.directory / "branch").symlink_to(external / "branch", target_is_directory=True)
        self.assertEqual(cleanup.apply_files(plan)["deleted_files"], 0)
        self.assertTrue((external / "branch/record.log").exists())
        with self.assertRaises(ValueError):
            self.plan(keep=[external])
        (self.directory / "branch").unlink()
        with self.assertRaises(ValueError):
            self.plan(keep=[".local/acceptance/../outside"])

    def test_new_symlink_not_followed_and_unrelated_source_preserved(self):
        external = self.root / "source.go"
        external.write_text("package main")
        (self.directory / "linked.log").symlink_to(external)
        self.file("old.log", "old")
        result = cleanup.apply_files(self.plan())
        self.assertEqual(result["deleted_files"], 1)
        self.assertEqual(external.read_text(), "package main")
        self.assertTrue((self.directory / "linked.log").is_symlink())

    def test_audit_exists_before_any_file_is_deleted(self):
        path = self.file("old.log", "old")
        original = cleanup.apply_files
        def apply(plan):
            records = list((self.root / ".local/cleanup").glob("*.json"))
            self.assertEqual(len(records), 1)
            self.assertEqual(json.loads(records[0].read_text())["status"], "planned")
            self.assertTrue(path.exists())
            return original(plan)
        with mock.patch.object(cleanup, "apply_files", side_effect=apply):
            report, result = cleanup.cleanup_local(self.root, current="v0.5.1", apply=True)
        self.assertEqual(result["status"], "passed")
        self.assertFalse(path.exists())
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)


def image(number, tag, *, parent="", architecture="amd64", created="2020-01-01T00:00:00Z"):
    return {"Id": "sha256:" + str(number) * 64, "Parent": parent, "RepoTags": [tag],
            "Created": created, "Size": 100, "Labels": {}, "Architecture": architecture, "Os": "linux"}


class DockerCleanupTests(unittest.TestCase):
    def test_remote_transport_failure_is_recorded_without_exposing_stderr(self):
        for code, text, status in [(127, "", "unavailable"), (0, "not-json", "unverified")]:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary).resolve()
                response = subprocess.CompletedProcess([], code, stdout=text, stderr="private-token-value")
                with mock.patch.object(cleanup, "ROOT", root), mock.patch.object(cleanup.subprocess, "run", return_value=response), mock.patch("sys.stdout", io.StringIO()):
                    result = cleanup.main(["docker", "--host", "home_dev", "--apply", "--directory", "/var/lib/starbeacon-acceptance/sbacc_1234567890abcdef", "--project", "sbacc_1234567890abcdef"])
                records = list((root / ".local/cleanup").glob("*.json"))
                self.assertEqual(result, 2)
                self.assertEqual(len(records), 1)
                self.assertEqual(json.loads(records[0].read_text())["status"], status)
                self.assertNotIn("private-token-value", records[0].read_text())

    def test_remote_identity_failure_prevents_any_docker_command(self):
        stream = io.StringIO()
        with mock.patch.object(cleanup, "__file__", "<stdin>"), \
             mock.patch.object(cleanup, "cleanup_docker") as docker, mock.patch("sys.stdout", stream):
            code = cleanup.main(["docker", "--apply", "--directory", "/not-owned", "--project", "sbacc_1234567890abcdef"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stream.getvalue())["status"], "unavailable")
        docker.assert_not_called()

    def test_only_owned_expired_exited_oneoff_containers_are_eligible(self):
        project = "sbacc_1234567890abcdef"
        good = {"Id": "one", "Image": "image", "Name": "/" + project + "-runner-1",
                "Labels": {"com.docker.compose.project": project, "com.docker.compose.oneoff": "True"},
                "State": {"Status": "exited", "FinishedAt": "2020-01-01T00:00:00Z"}}
        for replacement in [{"State": {"Status": "running"}}, {"Name": "/other-project-runner-1"},
                            {"Labels": {"com.docker.compose.project": project}},
                            {"State": {"Status": "exited", "FinishedAt": "unknown"}}]:
            with self.subTest(replacement=replacement):
                self.assertEqual(cleanup.expired_oneoffs([{**good, **replacement}]), [])
        self.assertEqual(cleanup.expired_oneoffs([good]), [good])

    def test_current_and_previous_are_distinct_versions(self):
        images = [image(1, "starbeacon/platform:0.5.1"), image(2, "starbeacon/platform:0.5.0"),
                  image(3, "starbeacon/platform:0.4.9"), image(4, "starbeacon/platform:0.5.1", created="2019-01-01T00:00:00Z")]
        plan = cleanup.docker_plan([], images)
        self.assertEqual({i["Id"] for i in plan["images"]}, {images[2]["Id"], images[3]["Id"]})

    def test_preview_does_not_displace_previous_stable_image(self):
        images = [image(1, "starbeacon/platform:0.5.1"), image(2, "starbeacon/platform:0.5.0"),
                  image(3, "starbeacon/platform:0.5.1-rc.10")]
        self.assertEqual([i["Id"] for i in cleanup.docker_plan([], images)["images"]], [images[2]["Id"]])

    def test_all_container_references_foreign_alias_and_parent_are_protected(self):
        parent = image(4, "shared:base")
        latest = image(1, "starbeacon/platform:0.5.1", parent=parent["Id"])
        old = image(2, "starbeacon/platform:0.5.0")
        historical = image(3, "starbeacon/platform:0.4.9")
        mixed = image(5, "starbeacon/agent:old")
        mixed["RepoTags"].append("another-project:stable")
        plan = cleanup.docker_plan([{"Image": historical["Id"], "State": {"Status": "exited"}}], [latest, old, historical, parent, mixed])
        self.assertNotIn(historical["Id"], {i["Id"] for i in plan["images"]})
        self.assertIn(parent["Id"], plan["protected_images"])
        self.assertIn(mixed["Id"], plan["protected_images"])

    def test_components_and_architectures_retained_independently(self):
        images = [image(1, "starbeacon/platform:0.5.1"), image(2, "starbeacon/platform:0.5.0"),
                  image(3, "starbeacon/platform:0.4.9", architecture="arm64"), image(4, "starbeacon/agent:0.3.0")]
        self.assertEqual(cleanup.docker_plan([], images)["images"], [])

    def test_old_container_does_not_make_current_or_previous_release_disposable(self):
        images = [image(1, "starbeacon/platform:0.5.1"), image(2, "starbeacon/platform:0.5.0"),
                  image(3, "starbeacon/platform:0.4.9"), image(4, "starbeacon/platform:0.4.8")]
        plan = cleanup.docker_plan([{"Image": images[2]["Id"]}], images)
        self.assertEqual([i["Id"] for i in plan["images"]], [images[3]["Id"]])

    def test_recent_unreferenced_image_and_unknown_timestamp_are_protected(self):
        images = [image(1, "starbeacon/platform:0.5.1"), image(2, "starbeacon/platform:0.5.0"),
                  image(3, "starbeacon/platform:0.4.9", created=datetime.datetime.now(datetime.timezone.utc).isoformat()),
                  image(4, "starbeacon/old:old", created="unknown")]
        self.assertEqual(cleanup.docker_plan([], images)["images"], [])

    def test_unavailable_daemon_does_not_start_or_prune_anything(self):
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            raise subprocess.CalledProcessError(1, args)
        self.assertEqual(cleanup.cleanup_docker(apply=True, command=command)["status"], "unavailable")
        self.assertEqual(calls, [["version", "--format", "{{.Server.Version}}"]])

    def test_changed_tag_and_new_reference_prevent_removal(self):
        old = image(3, "starbeacon/platform:0.4.9")
        calls = []
        def command(args, **kwargs):
            calls.append(args)
            if args[:3] == ["image", "inspect", "--format"]:
                return json.dumps("sha256:" + "9" * 64)
            raise AssertionError(args)
        with mock.patch.object(cleanup, "docker_inventory", return_value=([], [image(1, "starbeacon/platform:0.5.1"), image(2, "starbeacon/platform:0.5.0"), old])), \
             mock.patch.object(cleanup, "docker_containers", return_value=[]):
            result = cleanup.cleanup_docker(apply=True, command=command)
        self.assertEqual(result["status"], "partial")
        self.assertFalse(any(args[:2] == ["image", "rm"] for args in calls))
        with mock.patch.object(cleanup, "docker_inventory", return_value=([], [image(1, "starbeacon/platform:0.5.1"), image(2, "starbeacon/platform:0.5.0"), old])), \
             mock.patch.object(cleanup, "docker_containers", return_value=[{"Image": old["Id"]}]):
            result = cleanup.cleanup_docker(apply=True, command=command)
        self.assertEqual(result["results"][0]["status"], "protected_new_reference")

    def test_deletion_is_audited_non_force_and_does_not_prune_parents_or_volumes(self):
        old = image(3, "starbeacon/platform:0.4.9")
        calls, audits = [], []
        def command(args, **kwargs):
            self.assertEqual(len(audits), 1)
            calls.append(args)
            if args[:2] == ["image", "inspect"]:
                return json.dumps(old["Id"])
            if args[:3] == ["image", "rm", "--no-prune"]:
                return "Deleted"
            raise AssertionError(args)
        with mock.patch.object(cleanup, "docker_inventory", return_value=([], [image(1, "starbeacon/platform:0.5.1"), image(2, "starbeacon/platform:0.5.0"), old])), \
             mock.patch.object(cleanup, "docker_containers", return_value=[]):
            result = cleanup.cleanup_docker(apply=True, command=command, audit=audits.append)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(calls[-1], ["image", "rm", "--no-prune", "starbeacon/platform:0.4.9"])


class BuildCacheCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = pathlib.Path(self.temporary.name).resolve()
        self.project = "sbacc_1234567890abcdef"
        self.directory = self.base / self.project
        self.directory.mkdir()
        self.owner = {"schema_version": 1, "project": self.project, "storage": "persistent"}
        (self.directory / "owner.json").write_text(json.dumps(self.owner))
        self.patcher = mock.patch.object(cleanup, "CACHE_BASE", self.base)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        (self.directory / "go-build-cache").mkdir(mode=0o750)
        (self.directory / "go-build-cache/compiled").write_text("cache")
        (self.directory / "data").mkdir()
        (self.directory / "data/device.db").write_text("persistent")

    def test_project_marker_and_directory_must_match(self):
        cleanup.verify_remote_project(self.directory, self.project)
        with self.assertRaises(ValueError):
            cleanup.cleanup_build_cache(self.directory, "sbacc_ffffffffffffffff", apply=True)
        (self.directory / "owner.json").write_text(json.dumps({**self.owner, "project": "other"}))
        with self.assertRaises(ValueError):
            cleanup.cleanup_build_cache(self.directory, self.project, apply=True)
        self.assertTrue((self.directory / "go-build-cache/compiled").exists())

    def test_running_go_process_blocks_cleanup(self):
        with mock.patch.object(cleanup.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
            result = cleanup.cleanup_build_cache(self.directory, self.project, apply=True)
        self.assertEqual(result["status"], "busy")
        self.assertTrue((self.directory / "go-build-cache/compiled").exists())

    def test_unknown_process_status_fails_closed(self):
        with mock.patch.object(cleanup.subprocess, "run", return_value=subprocess.CompletedProcess([], 2)):
            with self.assertRaises(ValueError):
                cleanup.cleanup_build_cache(self.directory, self.project, apply=True)

    def test_actual_cache_deletion_preserves_state_permissions_and_link_target(self):
        outside = self.base / "outside.txt"
        outside.write_text("outside")
        (self.directory / "go-build-cache/link").symlink_to(outside)
        original_run = subprocess.run
        def run(arguments, **kwargs):
            if arguments[0] == "pgrep":
                return subprocess.CompletedProcess(arguments, 1)
            records = list((self.directory / "cleanup").glob("*.json"))
            self.assertEqual(len(records), 1)
            self.assertIn("quarantine", json.loads(records[0].read_text())["caches"][0])
            return original_run(arguments, **kwargs)
        before_mode = (self.directory / "go-build-cache").stat().st_mode & 0o777
        with mock.patch.object(cleanup.subprocess, "run", side_effect=run):
            result = cleanup.cleanup_build_cache(self.directory, self.project, apply=True)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(list((self.directory / "go-build-cache").iterdir()), [])
        self.assertEqual((self.directory / "go-build-cache").stat().st_mode & 0o777, before_mode)
        self.assertEqual((self.directory / "data/device.db").read_text(), "persistent")
        self.assertEqual(outside.read_text(), "outside")


if __name__ == "__main__":
    unittest.main()
