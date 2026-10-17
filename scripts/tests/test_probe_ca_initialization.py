"""只验证初始化目录、挂载和配置边界；合成文件不提供 CA 密码学验收。"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import init_step_ca as ca
import remote_acceptance


class ProbeCAInitializationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.parent = pathlib.Path(self.scratch.name)
        self.base = self.parent / "probe-pki"
        self.commands = []

    def docker(self, arguments, **options):
        self.commands.append((arguments, options))
        live = self.base / "ca"
        if "init" in arguments:
            (live / "config").mkdir()
            (live / "certs").mkdir()
            (live / "config/ca.json").write_text(json.dumps({"authority": {"provisioners": []}}))
            (live / "certs/root_ca.crt").write_text("synthetic public root")
            for name in ("root_ca_key", "intermediate_ca_key"):
                p = live / "secrets" / name
                p.write_text("synthetic encrypted key")
                p.chmod(0o600)
        else:
            (live / "provisioner.pub.json").write_text(json.dumps({"kty": "OKP", "crv": "Ed25519", "kid": "fixture-key", "x": "synthetic-public"}))
            (live / "platform-signing.jwk").write_text("synthetic private JWK")
        return subprocess.CompletedProcess(arguments, 0)

    def test_invalid_scope_does_not_create_any_output_or_run_docker(self):
        for dns in ("", "a,a", "a/b", "https://ca.example", "UPPER.example", "a..b", ".a", "-a", ",".join(str(n) for n in range(17))):
            with self.subTest(dns=dns), patch.object(ca.subprocess, "run") as run, self.assertRaises(ValueError):
                ca.initialize(self.base, dns)
            self.assertFalse(self.base.exists())
            run.assert_not_called()
        for location in ("relative", self.parent, self.parent / "missing/new"):
            with self.subTest(location=str(location)), self.assertRaises(ValueError):
                ca.initialize(location, "localhost")
        for uid, gid in ((0, 1000), (1000, 0), (-1, 1000)):
            with self.assertRaises(ValueError):
                ca.initialize(self.base, "localhost", uid=uid, gid=gid)
            self.assertFalse(self.base.exists())

    def test_ca_runtime_bounds_keep_offline_root_and_authorization_outside_ca(self):
        directory = '/tmp/starbeacon-acceptance-sbacc_' + 'a' * 16
        service = remote_acceptance.step_ca_service({'directory': directory, 'step_ca_image': 'sha256:' + 'b' * 64})
        self.assertTrue(service['read_only'])
        self.assertNotIn('ports', service)
        self.assertNotIn('privileged', service)
        self.assertEqual(service['cap_drop'], ['ALL'])
        self.assertEqual(service['cap_add'], ['NET_BIND_SERVICE'])
        for mount in service['volumes']:
            source, target, *flags = mount.split(':')
            self.assertTrue(source.startswith(directory + '/pki/ca/'))
            self.assertNotIn('offline', source)
            self.assertNotIn('platform', source)
            self.assertEqual(flags, [] if target == '/home/step/db' else ['ro'])

    @patch.object(ca.os, "chown")
    def test_runtime_mount_excludes_offline_root_and_platform_authorization(self, chown):
        with patch.object(ca.subprocess, "run", side_effect=self.docker):
            result = ca.initialize(self.base, "step-ca,localhost,127.0.0.1", uid=1000, gid=1000, platform_uid=65532, platform_gid=65532)
        self.assertEqual(result["image"], ca.IMAGE)
        self.assertTrue((self.base / "offline/root_ca_key").is_file())
        self.assertFalse((self.base / "ca/secrets/root_ca_key").exists())
        self.assertTrue((self.base / "ca/secrets/intermediate_ca_key").is_file())
        self.assertTrue((self.base / "platform/provisioner.jwk").is_file())
        self.assertFalse((self.base / "ca/platform-signing.jwk").exists())
        self.assertFalse((self.base / "ca/provisioner.pub.json").exists())
        for name in ("", "offline", "platform", "ca"):
            self.assertEqual((self.base / name).stat().st_mode & 0o777, 0o700)
        for name in ("deployment.json", "platform/provisioner.jwk", "ca/secrets/password", "ca/config/ca.json"):
            self.assertEqual((self.base / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(self.commands), 2)
        for arguments, options in self.commands:
            self.assertIn("none", arguments)
            self.assertIn("1000:1000", arguments)
            self.assertIn("no-new-privileges:true", arguments)
            self.assertNotIn(str(self.base / "offline"), " ".join(arguments))
            self.assertNotIn((self.base / "ca/secrets/password").read_text().strip(), " ".join(arguments))
            self.assertEqual(options["stdout"], subprocess.DEVNULL)
        config = json.loads((self.base / "ca/config/ca.json").read_text())
        provisioners = config["authority"]["provisioners"]
        self.assertEqual(len(provisioners), 1)
        self.assertEqual(provisioners[0]["name"], "starbeacon-probes")
        self.assertTrue(provisioners[0]["claims"]["disableRenewal"])
        self.assertEqual(config["tls"], {"minVersion": 1.3, "maxVersion": 1.3})
        self.assertIn(unittest.mock.call(self.base / "platform/provisioner.jwk", 65532, 65532), chown.call_args_list)
        with self.assertRaises(ValueError):
            ca.initialize(self.base, "localhost")

    @patch.object(ca.os, "chown")
    def test_failed_docker_preserves_private_directory_and_does_not_claim_deployment(self, _chown):
        with patch.object(ca.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["docker", "run"])), self.assertRaises(subprocess.CalledProcessError):
            ca.initialize(self.base, "localhost", uid=1000, gid=1000)
        self.assertTrue(self.base.is_dir())
        self.assertEqual(self.base.stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.base / "deployment.json").exists())
        with self.assertRaises(ValueError):
            ca.initialize(self.base, "localhost")


if __name__ == "__main__":
    unittest.main()
