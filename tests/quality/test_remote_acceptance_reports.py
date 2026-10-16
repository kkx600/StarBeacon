"""报告更新不能复用旧结论，也不能解包越界或链接目标。"""
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("remote_reports", ROOT / "scripts/remote_acceptance.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SOURCE = "a" * 64

def bundle(items=None, link=None):
    output = io.BytesIO()
    files = {"reports/source.json": json.dumps({"workspace_sha256": SOURCE}).encode()}
    files.update(items or {})
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, data in files.items():
            module.archive_bytes(archive, name, data)
        if link:
            value = tarfile.TarInfo(link[0])
            value.type, value.linkname = tarfile.SYMTYPE, link[1]
            archive.addfile(value)
    return output.getvalue()

class ReportsTests(unittest.TestCase):
    def test_runner_reaping_preserves_resource_and_namespace_boundaries(self):
        definition = {'services': {name: {} for name in (*module.DEPENDENCY_IMAGES, 'runner')}}
        definition['services']['runner'] = {'image':'fixture','init':False,'user':'65532:65532','pids_limit':96,'read_only':True,'cap_drop':['ALL'],'environment':{},'depends_on':{}}
        module.configure_runner({'project':'sbacc_1234567890abcdef','directory':'/tmp/starbeacon-acceptance-sbacc_1234567890abcdef'},definition)
        for name in ('runner','capture-runner'):
            service=definition['services'][name]
            self.assertTrue(service['init'])
            self.assertEqual(service['pids_limit'],96)
            self.assertTrue(service['read_only'])
            self.assertEqual(service['cap_drop'],['ALL'])
            self.assertNotIn('privileged',service)
            self.assertNotIn('pid',service)
        self.assertEqual(definition['services']['capture-runner']['cap_add'],['NET_RAW','SETFCAP'])

    def test_failed_run_replaces_reports_and_preserves_previous_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            prior = output / "reports"
            prior.mkdir()
            (prior / "backend.json").write_text('{"status":"passed"}')
            target = module.store_report_bundle(bundle(), output, SOURCE)
            self.assertFalse((target / "backend.json").exists())
            history = list(output.glob("reports-history-*"))
            self.assertEqual(len(history), 1)
            self.assertEqual(json.loads((history[0] / "backend.json").read_text())["status"], "passed")
            self.assertFalse(list(output.glob(".report-staging-*")))

    def test_mixed_snapshot_and_unsafe_members_leave_prior_evidence_intact(self):
        bad = [bundle({"reports/backend.json": json.dumps({"workspace_sha256": "b" * 64}).encode()}), bundle({"reports/../../escaped": b"bad"}), bundle({"unrelated/file": b"bad"}), bundle(link=("reports/link", "../../outside"))]
        for data in bad:
            with self.subTest(), tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory)
                (output / "reports").mkdir()
                (output / "reports/marker").write_text("preserve")
                with self.assertRaises(ValueError):
                    module.store_report_bundle(data, output, SOURCE)
                self.assertEqual((output / "reports/marker").read_text(), "preserve")
                self.assertFalse(list(output.glob("reports-history-*")))

    def test_output_link_and_wrong_source_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            linked = root / "linked"
            linked.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                module.store_report_bundle(bundle(), linked, SOURCE)
            with self.assertRaises(ValueError):
                module.store_report_bundle(bundle(), root, "b" * 64)

if __name__ == "__main__":
    unittest.main()
