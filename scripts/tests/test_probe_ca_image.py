"""官方 CA 镜像的分发来源和归档内容必须同时吻合。"""
import copy
import contextlib
import hashlib
import io
import json
import os
import pathlib
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import probe_ca_image as image


class ProbeCAImageTest(unittest.TestCase):
    def setUp(self):
        self.commit, self.run_id, self.repository = "a" * 40, "123", "owned/project"
        self.layer = b"fixed layer content"
        self.layer_digest = "sha256:" + hashlib.sha256(self.layer).hexdigest()
        self.config = json.dumps({"os": "linux", "architecture": "amd64", "rootfs": {"type": "layers", "diff_ids": [self.layer_digest]}}).encode()
        self.config_digest = "sha256:" + hashlib.sha256(self.config).hexdigest()
        self.metadata = {"Id": self.config_digest, "Os": "linux", "Architecture": "amd64",
                         "RepoDigests": [image.IMAGE.split(":0.30.2@")[0] + "@" + image.IMAGE.split("@")[1]],
                         "RootFS": {"Type": "layers", "Layers": [self.layer_digest]}}
        self.run = {"id": 123, "head_sha": self.commit, "head_branch": "main", "status": "completed", "conclusion": "success",
                    "event": "workflow_dispatch", "head_repository": {"full_name": self.repository}, "path": image.WORKFLOW}
        self.artifacts = {"artifacts": [{"name": image.ARTIFACT, "expired": False,
                                        "workflow_run": {"id": 123, "head_sha": self.commit, "head_branch": "main"}}]}

    def archive(self, directory, oci=False, corrupt_layer=False):
        config_name = "blobs/sha256/" + self.config_digest.split(":")[1] if oci else self.config_digest.split(":")[1] + ".json"
        layer_name = "blobs/sha256/" + self.layer_digest.split(":")[1] if oci else "layer/layer.tar"
        members = {config_name: self.config, layer_name: b"different content" if corrupt_layer else self.layer,
                   "manifest.json": json.dumps([{"Config": config_name, "Layers": [layer_name]}]).encode()}
        manifest_digest = None
        if oci:
            manifest = json.dumps({"schemaVersion": 2, "config": {"digest": self.config_digest, "size": len(self.config)},
                                   "layers": [{"digest": self.layer_digest, "size": len(self.layer)}]}).encode()
            manifest_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
            members["blobs/sha256/" + manifest_digest.split(":")[1]] = manifest
            members["index.json"] = json.dumps({"schemaVersion": 2, "manifests": [{"digest": manifest_digest, "size": len(manifest)}]}).encode()
        with tarfile.open(directory / image.ARCHIVE, "w:gz") as target:
            for name, data in members.items():
                member = tarfile.TarInfo(name); member.size = len(data)
                target.addfile(member, io.BytesIO(data))
        return manifest_digest

    def test_same_commit_distribution_and_archive_are_required(self):
        with tempfile.TemporaryDirectory() as scratch:
            directory = pathlib.Path(scratch).resolve()
            self.archive(directory)
            content = (directory / image.ARCHIVE).read_bytes()
            report = {"schema_version": 1, "scope": "official_probe_ca_image_distribution", "repository": self.repository,
                      "commit": self.commit, "run_id": self.run_id, "workflow": image.WORKFLOW,
                      "requested_image": image.IMAGE, "image": self.metadata,
                      "archive": {"name": image.ARCHIVE, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}}
            record = directory / "image.json"
            record.write_text(json.dumps(report))
            origin = {"run": self.run, "artifacts": self.artifacts}
            observed = image.verify(directory, origin, self.repository, self.commit, self.run_id)
            self.assertEqual({key: observed[key] for key in self.metadata}, self.metadata)
            self.assertEqual(observed["content_identity"]["load_ids"], [self.config_digest])
            for key, value in (("commit", "b" * 40), ("requested_image", "other/image:latest"), ("run_id", "124"), ("archive", None)):
                invalid = {**report, key: value}; record.write_text(json.dumps(invalid))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    image.verify(directory, origin, self.repository, self.commit, self.run_id)
            record.write_text(json.dumps(report))
            (directory / image.ARCHIVE).write_bytes(b"x" * len(content))
            with self.assertRaises(ValueError):
                image.verify(directory, origin, self.repository, self.commit, self.run_id)
            (directory / image.ARCHIVE).unlink()
            outside = directory / "outside"; outside.write_bytes(content)
            (directory / image.ARCHIVE).symlink_to(outside)
            with self.assertRaises(ValueError):
                image.verify(directory, origin, self.repository, self.commit, self.run_id)

    def test_classic_and_oci_store_identifiers_bind_the_same_configuration_and_layers(self):
        with tempfile.TemporaryDirectory() as scratch:
            directory = pathlib.Path(scratch).resolve()
            manifest = self.archive(directory, oci=True)
            identity = image.archive_identity(directory / image.ARCHIVE, self.metadata)
            self.assertEqual(identity["config_digest"], self.config_digest)
            self.assertEqual(identity["save_manifest_digest"], manifest)
            verified = {**self.metadata, "content_identity": identity}
            for identifier in (self.config_digest, manifest):
                self.assertEqual(image.verify_loaded({**self.metadata, "Id": identifier}, verified), identifier)
            for altered in ({**self.metadata, "Id": "sha256:" + "f" * 64}, {**self.metadata, "RootFS": {"Type": "layers", "Layers": []}}):
                with self.assertRaises(ValueError): image.verify_loaded(altered, verified)
            self.archive(directory, oci=True, corrupt_layer=True)
            with self.assertRaises(ValueError): image.archive_identity(directory / image.ARCHIVE, self.metadata)

    def test_other_workflows_repositories_commits_and_expired_material_are_rejected(self):
        image.verify_origin(self.run, self.artifacts, self.repository, self.commit, self.run_id)
        for key, value in {"head_sha": "b" * 40, "path": ".github/workflows/ci.yml", "event": "push", "status": "in_progress",
                           "conclusion": "failure", "head_branch": "other", "head_repository": {"full_name": "foreign/project"}}.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                image.verify_origin({**self.run, key: value}, self.artifacts, self.repository, self.commit, self.run_id)
        mutations = [lambda a: a.clear(), lambda a: a.append(copy.deepcopy(a[0])), lambda a: a[0].update(expired=True),
                     lambda a: a[0]["workflow_run"].update(head_sha="b" * 40), lambda a: a[0]["workflow_run"].update(id=124)]
        for mutate in mutations:
            artifacts = copy.deepcopy(self.artifacts); mutate(artifacts["artifacts"])
            with self.assertRaises(ValueError):
                image.verify_origin(self.run, artifacts, self.repository, self.commit, self.run_id)

    def test_wrong_platform_digest_and_layers_are_rejected(self):
        for key, value in {"Architecture": "arm64", "Os": "windows", "Id": "latest", "RepoDigests": [], "RootFS": {"Layers": []}}.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                image.verify_image({**self.metadata, key: value})

    def test_export_checks_context_before_docker_and_uses_save(self):
        parent = image.ROOT / ".local/acceptance"
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent, prefix="test-ca-image-") as scratch:
            directory = pathlib.Path(scratch) / "output"
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(image.subprocess, "run") as run:
                with self.assertRaises(ValueError): image.export(directory)
                run.assert_not_called()
            environment = {"GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
                           "GITHUB_REPOSITORY": self.repository, "GITHUB_SHA": self.commit, "GITHUB_RUN_ID": self.run_id,
                           "GITHUB_WORKFLOW_REF": self.repository + "/" + image.WORKFLOW + "@refs/heads/main"}
            calls = []
            def execute(arguments, **options):
                calls.append(arguments)
                if arguments[:3] == ["docker", "image", "save"]:
                    pathlib.Path(arguments[4]).write_bytes(b"docker image archive")
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(image.subprocess, "run", side_effect=execute), \
                    mock.patch.object(image.subprocess, "check_output", return_value=json.dumps([self.metadata]).encode()):
                with contextlib.redirect_stdout(io.StringIO()): image.export(directory)
                with self.assertRaises(ValueError): image.export(directory)
            self.assertEqual(calls[0], ["docker", "pull", "--platform", "linux/amd64", image.IMAGE])
            self.assertEqual(calls[1][-1], self.metadata["Id"])
            self.assertFalse((directory / "image.tar").exists())
            report = json.loads((directory / "image.json").read_text())
            self.assertEqual(report["archive"]["sha256"], image.sha256(directory / image.ARCHIVE))


if __name__ == "__main__":
    unittest.main()
