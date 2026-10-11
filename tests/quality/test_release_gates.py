"""以隔离的合成报告验证拒绝发布的边界，不作为产品功能验收证据。"""
import copy
import hashlib
import json
import pathlib
import stat
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
import check_acceptance as acceptance
import check_go_coverage as go_coverage
import check_package_acceptance as packages
import package_linux as packager
from test_go_dependencies import dependency_fixture

COMMIT = "a" * 40
VERSION = "v0.1.0"


class AcceptanceGateTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        self.reports = self.root / "reports"
        self.reports.mkdir()
        ids = [f"SB-DAT-{index:03}" for index in range(1, 108)]
        self.catalog = {"schema_version": 1, "requirements": [{"id": item} for item in ids]}
        (self.root / "docs").mkdir()
        (self.root / "docs/功能覆盖与验收矩阵.md").write_text("\n".join(ids))
        (self.root / "tests/acceptance").mkdir(parents=True)
        routes = {"platform": ["/alerts"], "collector": ["/network"]}
        (self.root / "tests/acceptance/routes.json").write_text(json.dumps(routes))
        (self.root / "internal").mkdir()
        (self.root / "internal/example.go").write_text("package example\nfunc useful() {}\n")
        profile = "mode: atomic\n" + go_coverage.MODULE + "internal/example.go:2.1,2.17 1 1\n"
        metrics = {key: {"total": 1, "covered": 1, "skipped": 0} for key in ("statements", "branches", "functions", "lines")}
        coverage = {}
        for app in ("platform", "collector", "packages/shared"):
            path = "web/" + app + "/src/example.ts"
            source = self.root / path
            source.parent.mkdir(parents=True)
            source.write_text("export const x = 1\n")
            coverage["/execution/" + path] = copy.deepcopy(metrics)
        coverage["total"] = {key: {"total": 3, "covered": 3, "skipped": 0} for key in metrics}
        evidence = self.evidence("assertions.json", '{"fixture_only":true}')
        self.report = {
            "schema_version": 1, "commit": COMMIT,
            "requirements": [{"id": item, "status": "passed", "checks": [{"name": "隔离的门禁测试夹具", "status": "passed", "execution": "real_service", "evidence": evidence}]} for item in ids],
            "coverage": {
                "go": {"statements": 100, "evidence": self.evidence("go.cover", profile)},
                "web": {**{metric: 100 for metric in metrics}, "source_root": "/execution", "evidence": self.evidence("coverage.json", json.dumps(coverage))},
            },
            "deployment": {"status": "passed", "environment": "remote_docker", "commit": COMMIT, "project": "sbacc_" + "f" * 16, "mode": "production", "evidence": evidence,
                           **{key: True for key in ("tls_verified", "runtime_role_verified", "native_isolation_verified", "private_network_verified", "clean_commit")}},
            "screens": [{"app": app, "width": width, "height": 900, "status": "passed", "overflow_count": 0, "evidence": evidence,
                         "routes": [{"path": path, "status": "passed", "interactions": [{"name": "隔离的交互断言夹具", "status": "passed"}]} for path in paths]}
                        for app, paths in routes.items() for width in acceptance.SCREEN_WIDTHS],
        }
        self.scope = patch.object(acceptance, "ROOT", self.root)
        self.scope.start()
        self.addCleanup(self.scope.stop)

    def evidence(self, name, content):
        path = self.reports / name
        path.write_text(content)
        return {"path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def test_complete_fixture_passes_gate(self):
        self.assertEqual(acceptance.verify(self.report, COMMIT, self.catalog, self.reports), [])

    def test_incomplete_or_mocked_requirement_rejected(self):
        mutations = [
            lambda r: r["requirements"].pop(),
            lambda r: r["requirements"].append(copy.deepcopy(r["requirements"][0])),
            lambda r: r["requirements"][0].update(status="skipped"),
            lambda r: r["requirements"][0].update(checks=[]),
            lambda r: r["requirements"][0]["checks"][0].update(execution="mock"),
            lambda r: r["requirements"][0]["checks"][0].update(name="  "),
            lambda r: r["requirements"][0]["checks"][0].update(status="failed"),
            lambda r: r.update(requirements=[None]),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(self.report)
                mutation(report)
                self.assertTrue(acceptance.verify(report, COMMIT, self.catalog, self.reports))

    def test_wrong_commit_catalog_or_schema_rejected(self):
        for changes in ({"commit": "b" * 40}, {"schema_version": True}, {"schema_version": 2}):
            self.assertTrue(acceptance.verify({**self.report, **changes}, COMMIT, self.catalog, self.reports))
        self.assertTrue(acceptance.verify(self.report, "a" * 7, self.catalog, self.reports))
        for catalog in (None, {"schema_version": 1, "requirements": []}, {"schema_version": True, "requirements": self.catalog["requirements"]}, {"requirements": [{"id": []}]}):
            self.assertTrue(acceptance.verify(self.report, COMMIT, catalog, self.reports))

    def test_coverage_cannot_trust_percentage_or_skip_source(self):
        for value in (89.99, True, float("nan"), float("inf"), 101, "100"):
            report = copy.deepcopy(self.report)
            report["coverage"]["go"]["statements"] = value
            self.assertTrue(acceptance.verify(report, COMMIT, self.catalog, self.reports))
        report = copy.deepcopy(self.report)
        profile = (self.reports / "go.cover").read_text().replace(" 1 1", " 1 0")
        report["coverage"]["go"]["evidence"] = self.evidence("zero.cover", profile)
        self.assertTrue(acceptance.verify(report, COMMIT, self.catalog, self.reports))
        (self.root / "internal/uncovered.go").write_text("package example\nfunc omitted() {}\n")
        self.assertTrue(acceptance.verify(self.report, COMMIT, self.catalog, self.reports))

    def test_frontend_counts_paths_and_skips_rejected(self):
        original = json.loads((self.reports / "coverage.json").read_text())
        mutations = [
            lambda c: c["total"]["lines"].update(covered=2),
            lambda c: c["total"]["lines"].update(skipped=1),
            lambda c: c["total"]["lines"].update(covered=True),
            lambda c: c.pop("/execution/web/platform/src/example.ts"),
            lambda c: c.update({"/execution/../external.ts": copy.deepcopy(c["total"])}),
            lambda c: c.update({"/other/web/platform/src/example.ts": copy.deepcopy(c["total"])}),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                data = copy.deepcopy(original)
                mutation(data)
                with self.assertRaises((ValueError, KeyError)):
                    acceptance.web_coverage(data, "/execution", self.root)
        for source in ("execution", "/execution/../source"):
            with self.assertRaises(ValueError):
                acceptance.web_coverage(original, source, self.root)

    def test_development_or_unverified_remote_deployment_rejected(self):
        for key, value in [("mode", "development"), ("project", "shared"), ("environment", "local"), ("commit", "b" * 40),
                           *[(flag, False) for flag in ("tls_verified", "runtime_role_verified", "native_isolation_verified", "private_network_verified", "clean_commit")]]:
            with self.subTest(key=key):
                report = copy.deepcopy(self.report)
                report["deployment"][key] = value
                self.assertTrue(acceptance.verify(report, COMMIT, self.catalog, self.reports))

    def test_screen_routes_and_interactions_are_required(self):
        mutations = [
            lambda r: r["screens"].pop(),
            lambda r: r["screens"].append(copy.deepcopy(r["screens"][0])),
            lambda r: r["screens"][0].update(width=1023),
            lambda r: r["screens"][0].update(height=767),
            lambda r: r["screens"][0].update(overflow_count=1),
            lambda r: r["screens"][0].update(overflow_count=False),
            lambda r: r["screens"][0].update(routes=[]),
            lambda r: r["screens"][0]["routes"][0].update(path="/unknown"),
            lambda r: r["screens"][0]["routes"].append(copy.deepcopy(r["screens"][0]["routes"][0])),
            lambda r: r["screens"][0]["routes"][0].update(interactions=[None]),
            lambda r: r["screens"][0]["routes"][0].update(interactions=[]),
            lambda r: r["screens"][0]["routes"][0]["interactions"][0].update(status="failed"),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(self.report)
                mutation(report)
                self.assertTrue(acceptance.verify(report, COMMIT, self.catalog, self.reports))

    def test_evidence_digest_and_containment(self):
        for evidence in (None, {"path": "/etc/passwd", "sha256": "a" * 64}, {"path": "../escape", "sha256": "a" * 64},
                         {"path": "missing", "sha256": "a" * 64}, {"path": "assertions.json", "sha256": "a" * 64}):
            with self.assertRaises(ValueError):
                acceptance.verify_evidence(self.reports, evidence)
        outside = self.root / "outside"
        outside.write_text("外部证据")
        (self.reports / "link").symlink_to(outside)
        with self.assertRaises(ValueError):
            acceptance.verify_evidence(self.reports, {"path": "link", "sha256": hashlib.sha256(outside.read_bytes()).hexdigest()})


class GoCoverageGateTests(unittest.TestCase):
    def test_merge_current_profiles_rejects_changed_source_layout(self):
        block = go_coverage.MODULE + "internal/real.go:2.1,2.17"
        merged = go_coverage.merge_profiles([f"mode: atomic\n{block} 2 0\n", f"mode: atomic\n{block} 2 3\n"])
        self.assertEqual(go_coverage.summarize(merged)["percentage"], 100)
        for profile in (f"mode: count\n{block} 2 3\n", f"mode: atomic\n{block} 3 3\n", f"mode: atomic\n{block} 2 3\n{go_coverage.MODULE}internal/real.go:3.1,3.17 1 0\n"):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                go_coverage.merge_profiles([merged, profile])
        for profiles in ([], [""], ["mode: atomic\n"]):
            with self.assertRaises(ValueError):
                go_coverage.merge_profiles(profiles)

    def test_merge_duplicate_blocks_uses_union(self):
        prefix = go_coverage.MODULE + "internal/real.go:2.1,2.17"
        report = go_coverage.summarize(f"mode: atomic\n{prefix} 2 0\n{prefix} 2 3\n" + go_coverage.MODULE + "api/sensor/generated.go:1.1,2.1 100 0\n")
        self.assertEqual((report["total"], report["covered"], report["percentage"]), (2, 2, 100))

    def test_invalid_profiles_are_rejected(self):
        prefix = go_coverage.MODULE
        for record in ("", "mode: invalid", "mode: atomic\nother/repo.go:1.1,1.2 1 1", *["mode: atomic\n" + prefix + suffix for suffix in (
            "internal/x.go:0.1,1.2 1 1", "internal/x.go:2.1,1.2 1 1", "internal/../x.go:1.1,1.2 1 1",
            "internal//x.go:1.1,1.2 1 1", "internal/x_test.go:1.1,1.2 1 1", "internal/x.txt:1.1,1.2 1 1",
            "internal/x.go:1.1,1.2 -1 1", "internal/x.go:1.1,1.2 1 -1", "external/x.go:1.1,1.2 1 1",
            "internal/x.go:1.1,1.2 1 1\n" + prefix + "internal/x.go:1.1,1.2 2 0")]):
            with self.subTest(record=record), self.assertRaises(ValueError):
                go_coverage.summarize(record)

    def test_invented_file_and_position_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            (root / "internal").mkdir()
            source = root / "internal/real.go"
            source.write_text("package real\nfunc actual() {}\n")
            for location in ("internal/missing.go:1.1,1.2", "internal/real.go:1.1,99.1", "internal/real.go:2.1,2.99"):
                with self.subTest(location=location), self.assertRaises(ValueError):
                    go_coverage.check_sources(go_coverage.summarize(f"mode: atomic\n{go_coverage.MODULE}{location} 1 1\n"), root)

    def test_build_target_uses_official_files_without_omitting_zero_coverage(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            (root / "internal").mkdir()
            (root / "go.mod").write_text("module github.com/kkx600/StarBeacon\ngo 1.26.0\n")
            for filename in ("real.go", "capture_linux.go", "capture_other.go"):
                (root / "internal" / filename).write_text("package real\nfunc actual() {}\n")
            package = {"ImportPath": go_coverage.MODULE + "internal", "Dir": str(root / "internal"), "GoFiles": ["real.go", "capture_linux.go"], "IgnoredGoFiles": ["capture_other.go"]}
            raw = json.dumps(package)
            with patch.object(go_coverage.subprocess, "run", return_value=go_coverage.subprocess.CompletedProcess([], 0, raw, "")) as process:
                profile = "mode: atomic\n" + "".join(f"{go_coverage.MODULE}internal/{filename}:2.1,2.17 1 {count}\n" for filename, count in (("real.go", 1), ("capture_linux.go", 0)))
                go_coverage.check_sources(go_coverage.summarize(profile), root)
                self.assertEqual(go_coverage.summarize(profile)["percentage"], 50)
                with self.assertRaisesRegex(ValueError, "缺少自有源码"):
                    go_coverage.check_sources(go_coverage.summarize(f"mode: atomic\n{go_coverage.MODULE}internal/real.go:2.1,2.17 1 1\n"), root)
                with self.assertRaisesRegex(ValueError, "其他构建目标"):
                    go_coverage.check_sources(go_coverage.summarize(profile + f"{go_coverage.MODULE}internal/capture_other.go:2.1,2.17 1 1\n"), root)
                environment = process.call_args.kwargs["env"]
                self.assertEqual((environment["GOWORK"], environment["GOPROXY"], environment["GOFLAGS"]), ("off", "off", ""))

    def test_unavailable_or_malformed_compiler_inventory_cannot_pass(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            (root / "go.mod").write_text("module github.com/kkx600/StarBeacon\n")
            with patch.object(go_coverage.subprocess, "run", side_effect=OSError("不可用")):
                with self.assertRaisesRegex(ValueError, "无法核对"):
                    go_coverage.compiled_sources(root)

    def test_no_test_packages_use_compiler_test_file_selection(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            (root / "go.mod").write_text("module github.com/kkx600/StarBeacon\n")
            (root / "internal").mkdir()
            for filename in ("real.go", "real_test.go"):
                (root / "internal" / filename).write_text("package real\n")
            package = {"ImportPath": go_coverage.MODULE + "internal", "Dir": str(root / "internal"), "GoFiles": ["real.go"], "IgnoredGoFiles": ["real_test.go"]}
            run = lambda raw: patch.object(go_coverage.subprocess, "run", return_value=go_coverage.subprocess.CompletedProcess([], 0, json.dumps(raw), ""))
            with run(package):
                self.assertEqual(go_coverage.packages_without_tests(root), {package["ImportPath"]})
            for field in ("TestGoFiles", "XTestGoFiles"):
                with self.subTest(field=field), run(dict(package, **{field: ["real_test.go"]})):
                    self.assertEqual(go_coverage.packages_without_tests(root), set())
                with run(dict(package, **{field: ["real.go"]})), self.assertRaises(ValueError):
                    go_coverage.packages_without_tests(root)
            with self.assertRaises(ValueError):
                go_coverage.packages_without_tests(root / "missing")
            for output in ("", "{", "[]", json.dumps({"ImportPath": "external/module", "Dir": str(root)}), json.dumps({"ImportPath": go_coverage.MODULE + "internal", "Dir": str(root.parent), "GoFiles": ["other.go"]}), json.dumps({"ImportPath": go_coverage.MODULE + "internal", "Dir": str(root), "GoFiles": ["../other.go"]})):
                with self.subTest(output=output), patch.object(go_coverage.subprocess, "run", return_value=go_coverage.subprocess.CompletedProcess([], 0, output, "")), self.assertRaises(ValueError):
                    go_coverage.compiled_sources(root)


class PackageGateTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        self.report = {"commit": COMMIT, "packages": []}
        self.checksums = {"commit": COMMIT, "version": VERSION, "archives": []}
        evidence = self.root / "test.json"
        evidence.write_text('{"fixture_only":true}')
        proof = {"path": "test.json", "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest()}
        for bundle, roles in packager.ROLES.items():
            source = self.root / ("starbeacon-" + bundle)
            (source / "bin").mkdir(parents=True)
            (source / "www").mkdir()
            (source / "config").mkdir()
            (source / "README.md").write_text("测试夹具")
            (source / "LICENSE").write_text("隔离的合成项目许可夹具，不作为产品发行许可。")
            (source / "www/index.html").write_text("<html></html>")
            license_text = "隔离的合成依赖许可夹具，不作为第三方许可证明。"
            frontend = [{"name": "fixture-only", "version": "0.0.0", "identifier": "MIT", "text": license_text, "sha256": hashlib.sha256(license_text.encode()).hexdigest()}]
            (source / "www/third-party-licenses.json").write_text(json.dumps(frontend))
            (source / "config/nginx.conf").write_text("测试夹具")
            metadata = {"schema_version": 1, "version": VERSION, "commit": COMMIT, "os": "linux", "arch": "amd64", "go": packager.GO_VERSION, "upx": packager.UPX_VERSION, "binaries": {}}
            metadata["project_license"] = {"path": "LICENSE", "sha256": packager.digest(source / "LICENSE")}
            metadata["frontend_licenses"] = {"path": "www/third-party-licenses.json", "sha256": packager.digest(source / "www/third-party-licenses.json"), "count": 1}
            for role in roles:
                # 仅测试校验器的文件类型与摘要分支，不执行合成 ELF 或声称它是产品程序。
                binary = bytearray(20)
                binary[:6] = b"\x7fELF\x02\x01"
                binary[18:20] = struct.pack("<H", 62)
                (source / "bin" / role).write_bytes(binary)
                (source / "bin" / (role + ".buildinfo.txt")).write_text("测试工具链信息")
                metadata["binaries"][role] = {"sha256": hashlib.sha256(binary).hexdigest(), "uncompressed_sha256": "b" * 64, "size": len(binary), "uncompressed_size": 40, "version_check": "passed", "upx_check": "passed"}
            dependency_fixture(source, metadata, roles)
            (source / "manifest.json").write_text(json.dumps(metadata))
            archive = self.root / f"starbeacon-{bundle}-{VERSION}-linux-amd64.zip"
            packager.archive(source, archive, 1_700_000_000)
            record = {"name": archive.name, "size": archive.stat().st_size, "sha256": packager.digest(archive)}
            self.checksums["archives"].append(record)
            self.report["packages"].append({**record, "status": "passed", "execution": "remote_docker", "binaries": "upx_compressed", "version": VERSION, "evidence": proof})

    def verify(self):
        packages.verify(self.report, self.checksums, self.root, self.root)

    def update_record(self, index):
        record = self.checksums["archives"][index]
        archive = self.root / record["name"]
        record.update(size=archive.stat().st_size, sha256=packager.digest(archive))
        self.report["packages"][index].update(record)

    def test_package_files_and_buildinfo_permissions(self):
        self.verify()
        with zipfile.ZipFile(self.root / self.checksums["archives"][0]["name"]) as archive:
            self.assertEqual(stat.S_IMODE(archive.getinfo("starbeacon-platform/bin/starbeacon.buildinfo.txt").external_attr >> 16), 0o644)

    def test_incomplete_or_unverified_packages_rejected(self):
        original = copy.deepcopy(self.report)
        for key, value in (("status", "skipped"), ("execution", "local"), ("binaries", "uncompressed"), ("version", "v0.2.0"), ("sha256", "f" * 64)):
            self.report = copy.deepcopy(original)
            self.report["packages"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()
        for records in ([], [original["packages"][0]], [original["packages"][0], original["packages"][0]], [None, None]):
            self.report = {**original, "packages": records}
            with self.assertRaises(ValueError):
                self.verify()

    def test_actual_zip_tampering_is_rejected(self):
        path = self.root / self.checksums["archives"][0]["name"]
        path.write_bytes(path.read_bytes() + "被篡改的尾部".encode())
        with self.assertRaises(ValueError):
            self.verify()

    def test_frontend_license_identity_and_text_digest_are_required(self):
        text = "合成许可校验夹具"
        record = {"name": "fixture", "version": "1", "identifier": "MIT", "text": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}
        self.assertEqual(packager.frontend_licenses(json.dumps([record]).encode()), 1)
        values = [[], {}, [None], [record, record], [{**record, "sha256": "a" * 64}], [{**record, "text": ""}], [{**record, "version": ""}], [{**record, "identifier": "UNKNOWN"}], [{**record, "identifier": "UNLICENSED"}]]
        for records in values:
            with self.subTest(records=records), self.assertRaises(ValueError):
                packager.frontend_licenses(json.dumps(records).encode())
        for content in (b"", b"\xff", b"[", b" " * (4 * 1024 * 1024 + 1)):
            with self.assertRaises(ValueError):
                packager.frontend_licenses(content)

    def test_zip_license_documents_are_required_and_bound(self):
        source = self.root / "starbeacon-platform"
        path = self.root / self.checksums["archives"][0]["name"]
        original = {name: (source / name).read_bytes() for name in ("LICENSE", "manifest.json", "www/third-party-licenses.json")}
        mutations = [
            ("LICENSE", None), ("LICENSE", b"changed fixture license"), ("LICENSE", b" \n"),
            ("www/third-party-licenses.json", None), ("www/third-party-licenses.json", b"[]"),
        ]
        metadata = json.loads(original["manifest.json"])
        for field, value in (("project_license", None), ("project_license", {"path": "../LICENSE", "sha256": "a" * 64}), ("frontend_licenses", None), ("frontend_licenses", {**metadata["frontend_licenses"], "count": True}), ("frontend_licenses", {**metadata["frontend_licenses"], "count": 2})):
            mutations.append(("manifest.json", json.dumps({**metadata, field: value}).encode()))
        for name, content in mutations:
            for filename, body in original.items():
                (source / filename).write_bytes(body)
            if content is None:
                (source / name).unlink()
            else:
                (source / name).write_bytes(content)
            packager.archive(source, path, 1_700_000_000)
            self.update_record(0)
            with self.subTest(name=name, content=content), self.assertRaises(ValueError):
                self.verify()

    def test_archive_traversal_duplicate_and_symlink_rejected(self):
        path = self.root / self.checksums["archives"][0]["name"]
        original = path.read_bytes()
        for name, mode in (("../escape", 0o100644), ("starbeacon-platform/../escape", 0o100644), ("starbeacon-platform/link", 0o120777), ("starbeacon-platform/README.md", 0o100644)):
            path.write_bytes(original)
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = mode << 16
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "a") as archive:
                    archive.writestr(info, "不可信内容".encode())
            self.update_record(0)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify()

    def test_zip_packager_rejects_symlink(self):
        source = self.root / "symlink-source"
        source.mkdir()
        (source / "link").symlink_to(self.root / "test.json")
        with self.assertRaises(ValueError):
            packager.archive(source, self.root / "unsafe.zip", 1_700_000_000)


if __name__ == "__main__":
    unittest.main()
