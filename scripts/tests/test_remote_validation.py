import argparse
import io
import json
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import remote_validation as validation


class RemoteValidationTests(unittest.TestCase):
    def setUp(self):
        self.directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_sync_preserves_commit_and_uncommitted_source(self):
        repository = self.directory / "repository"
        repository.mkdir()

        def git(*arguments):
            return subprocess.check_output(["git", "-C", str(repository), *arguments], stderr=subprocess.STDOUT).decode().strip()

        git("init", "-q")
        git("config", "user.name", "验收")
        git("config", "user.email", "acceptance@example.test")
        (repository / ".gitignore").write_text(".env\n")
        (repository / "changed.txt").write_text("提交版本\n")
        (repository / "deleted.txt").write_text("即将删除\n")
        git("add", ".")
        git("commit", "-qm", "验收起点")
        commit = git("rev-parse", "HEAD")
        (repository / "changed.txt").write_text("当前工作区\n")
        (repository / "deleted.txt").unlink()
        (repository / "new.txt").write_text("尚未暂存\n")
        (repository / ".env").write_text("不在验收快照内\n")

        archive = self.directory / "source.tar"
        with patch.object(validation, "ROOT", repository):
            identity = validation.prepare_source(archive, frontend=False)

        staging = self.directory / "staging"
        staging.mkdir()
        with tarfile.open(archive) as bundle:
            bundle.extractall(staging, filter="data")
        subprocess.run([sys.executable, "-c", validation.INITIALIZE, str(staging), commit],
                       stdout=subprocess.DEVNULL, check=True)
        source = staging / "source"
        self.assertEqual(subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip(), commit)
        self.assertEqual((source / "changed.txt").read_text(), "当前工作区\n")
        self.assertFalse((source / "deleted.txt").exists())
        self.assertEqual((source / "new.txt").read_text(), "尚未暂存\n")
        self.assertFalse((source / ".env").exists())
        self.assertFalse(identity["clean_commit"])
        self.assertEqual(json.loads((staging / "reports/source.json").read_text()), identity)

    def test_backend_fetches_reports_after_test_failure(self):
        state = self.directory / "state.json"
        state.touch()
        output = self.directory / "backend"
        args = argparse.Namespace(backend_state=state, host="home_dev", backend_build="remote")
        identity = {"host": args.host, "commit": "a" * 40, "workspace_sha256": "b" * 64}

        with patch.object(validation.acceptance, "read_state", return_value=identity), \
                patch.object(validation, "command", side_effect=(True, False, True)) as command:
            self.assertFalse(validation.backend_checks(args, output, {"steps": []}))
        self.assertEqual([call.args[2] for call in command.call_args_list], ["sync", "run", "fetch"])
        self.assertEqual(command.call_args.args[3][-2:], ["--report-output", str(output)])

    def test_all_binds_each_group_to_the_frozen_sources(self):
        args = argparse.Namespace()
        report = {"groups": {group: {"steps": []} for group in validation.GROUPS}}
        identity = {"commit": "a" * 40, "workspace_sha256": "b" * 64}
        backend_digest = "c" * 64

        def prepare(archive, *, frontend):
            self.assertTrue(frontend)
            archive.write_bytes(b"frozen")
            return identity

        def remote(_args, _output, groups, _results, source):
            self.assertEqual(groups, ["frontend", "contract"])
            archive, captured = source
            self.assertEqual(archive.read_bytes(), b"frozen")
            self.assertEqual(captured, identity)
            return True

        with patch.object(validation, "prepare_source", side_effect=prepare), \
                patch.object(validation.acceptance, "snapshot_sources", return_value=({}, backend_digest)), \
                patch.object(validation, "backend_checks", return_value=True) as backend, \
                patch.object(validation, "run_remote_checks", side_effect=remote):
            self.assertTrue(validation.run_selected_groups(args, self.directory, report))
        self.assertEqual(backend.call_args.args[-1], (identity["commit"], backend_digest))

    def test_workspace_runs_next_group_and_fetches_failure_evidence(self):
        args = argparse.Namespace(host="home_dev", toolchain_path="/pinned/bin")
        results = {"frontend": {"steps": []}, "contract": {"steps": []}}
        identity = {"commit": "a" * 40, "workspace_sha256": "b" * 64, "clean_commit": True}
        runtime = "/var/tmp/starbeacon-validation-quv450SJABXZ"
        output = self.directory / "host"
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            validation.acceptance.archive_bytes(archive, "reports/source.json", json.dumps(identity).encode())

        def synchronize(archive, *, frontend):
            self.assertTrue(frontend)
            archive.write_bytes(b"fixture")
            return identity

        calls = []

        def ssh(host, command, **options):
            calls.append(command)
            if command[0] == "mktemp":
                return subprocess.CompletedProcess(command, 0, stdout=(runtime + "\n").encode())
            if command[0] == "tar" and command[1] == "-czf":
                return subprocess.CompletedProcess(command, 0, stdout=data.getvalue())
            if "--worker" in command and "frontend" in command:
                raise subprocess.CalledProcessError(1, command)
            return subprocess.CompletedProcess(command, 0)

        with patch.object(validation, "prepare_source", side_effect=synchronize), \
                patch.object(validation, "runner_ssh", side_effect=ssh):
            self.assertFalse(validation.run_remote_checks(args, output, ["frontend", "contract"], results))
        self.assertEqual(results["frontend"]["status"], "failed")
        self.assertEqual(results["contract"]["status"], "passed")
        self.assertEqual(json.loads((output / "reports/source.json").read_text()), identity)
        self.assertEqual(calls[-1], ["rm", "-rf", "--", runtime])
