"""以隔离的合成夹具验证发布核对与覆盖率统计的拒绝边界，不作为产品功能验收证据。"""
import contextlib
import copy
import hashlib
import io
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
import check_go_coverage as go_coverage
import check_release as release
import package_linux as packager
import qualify_frontend as frontend
from test_go_dependencies import dependency_fixture
COMMIT = "a" * 40
VERSION = "v0.1.0"
REPOSITORY = "kkx600/StarBeacon"
RUN_URL = "https://github.com/kkx600/StarBeacon/actions/runs/1234"


class FrontendCoverageTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        metrics = {key: {"total": 1, "covered": 1, "skipped": 0} for key in ("statements", "branches", "functions", "lines")}
        self.coverage = {}
        for app in ("platform", "collector", "packages/shared"):
            path = "web/" + app + "/src/example.ts"
            source = self.root / path
            source.parent.mkdir(parents=True)
            source.write_text("export const x = 1\n")
            self.coverage["/execution/" + path] = copy.deepcopy(metrics)
        self.coverage["total"] = {key: {"total": 3, "covered": 3, "skipped": 0} for key in metrics}

    def test_complete_coverage_reports_each_metric(self):
        self.assertEqual(frontend.web_coverage(self.coverage, "/execution", self.root), {key: 100 for key in ("statements", "branches", "functions", "lines")})

    def test_frontend_counts_paths_and_skips_rejected(self):
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
                data = copy.deepcopy(self.coverage)
                mutation(data)
                with self.assertRaises((ValueError, KeyError)):
                    frontend.web_coverage(data, "/execution", self.root)
        for source in ("execution", "/execution/../source"):
            with self.assertRaises(ValueError):
                frontend.web_coverage(self.coverage, source, self.root)

    def test_uncovered_source_cannot_be_omitted(self):
        (self.root / "web/collector/src/omitted.vue").write_text("<template><div/></template>\n")
        with self.assertRaisesRegex(ValueError, "缺少源码"):
            frontend.web_coverage(self.coverage, "/execution", self.root)


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


class FakeGitHub:
    """按路径返回合成 API 响应并记录调用；不访问 GitHub。"""

    def __init__(self, version=VERSION, tag=None, compare="behind", releases=()):
        self.version = version
        self.objects = {}
        self.tag = tag or {"type": "commit", "sha": COMMIT}
        self.compare = compare
        self.releases = list(releases)
        self.calls = []

    def __call__(self, path, method="GET"):
        self.calls.append((method, path))
        prefix = f"repos/{REPOSITORY}/"
        if method == "GET" and path == prefix + f"git/ref/tags/{self.version}":
            return {"ref": "refs/tags/" + self.version, "object": self.tag}
        if method == "GET" and path.startswith(prefix + "git/tags/"):
            return {"object": self.objects.get(path.rsplit("/", 1)[1])}
        if method == "GET" and path.startswith(prefix + "compare/main..."):
            return {"status": self.compare}
        if method == "GET" and path == prefix + "releases?per_page=100":
            return self.releases
        if method == "DELETE" and path.startswith(prefix + "releases/"):
            return None
        raise AssertionError(f"未预期的 API 调用：{method} {path}")


class ReleaseIdentityTests(unittest.TestCase):
    def test_version_format_and_prerelease(self):
        for version, prerelease in (("v0.1.0", False), ("v12.0.3", False), ("v1.2.3-rc.1", True), ("v0.2.0-beta-2", True)):
            with self.subTest(version=version):
                self.assertIs(release.validate_version(version), prerelease)
        for version in ("0.1.0", "v0.1", "v01.0.0", "v0.1.0+build.1", "v0.1.0-", "v0.1.0-rc..1", "../v0.1.0", "v0.1.0\n", "v1.0.0-" + "a" * 60, None, 1):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.validate_version(version)

    def test_lightweight_and_annotated_tags_resolve_to_commit(self):
        api = FakeGitHub()
        self.assertEqual(release.identity(VERSION, REPOSITORY, COMMIT, api), {"version": VERSION, "commit": COMMIT, "prerelease": "false"})
        tag = "b" * 40
        api = FakeGitHub(version="v0.2.0-rc.1", tag={"type": "tag", "sha": tag})
        api.objects[tag] = {"type": "commit", "sha": COMMIT}
        for sha in (tag, COMMIT):
            with self.subTest(sha=sha):
                self.assertEqual(release.identity("v0.2.0-rc.1", REPOSITORY, sha, api)["commit"], COMMIT)
        self.assertIn(("GET", f"repos/{REPOSITORY}/compare/main...{COMMIT}"), api.calls)

    def test_moved_tag_unmerged_commit_and_invalid_objects_rejected(self):
        with self.assertRaisesRegex(ValueError, "其他提交"):
            release.identity(VERSION, REPOSITORY, "c" * 40, FakeGitHub())
        for status in ("ahead", "diverged", None):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "main"):
                release.identity(VERSION, REPOSITORY, COMMIT, FakeGitHub(compare=status))
        for tag in ({"type": "tree", "sha": COMMIT}, {"type": "commit", "sha": "short"}, {"type": "commit"}, {"type": "tag", "sha": "d" * 40}):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "有效提交"):
                release.identity(VERSION, REPOSITORY, COMMIT, FakeGitHub(tag=tag))
        for args in ((VERSION, "owner/repo/other", COMMIT), (VERSION, REPOSITORY, "main"), ("main", REPOSITORY, COMMIT)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                release.identity(*args, FakeGitHub())

    def test_identity_command_writes_step_outputs(self):
        output = io.StringIO()
        with patch.object(release, "gh_api", FakeGitHub()), contextlib.redirect_stdout(output):
            self.assertEqual(release.main(["identity", "--version", VERSION, "--repository", REPOSITORY, "--sha", COMMIT]), 0)
        self.assertEqual(output.getvalue().splitlines(), [f"version={VERSION}", f"commit={COMMIT}", "prerelease=false"])
        errors = io.StringIO()
        with patch.object(release, "gh_api", FakeGitHub(compare="diverged")), contextlib.redirect_stderr(errors):
            self.assertEqual(release.main(["identity", "--version", VERSION, "--repository", REPOSITORY, "--sha", COMMIT]), 1)
        self.assertIn("发布核对失败", errors.getvalue())


class PackageGateTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        self.checksums = {"commit": COMMIT, "version": VERSION, "archives": []}
        for bundle, roles in packager.ROLES.items():
            source = self.root / "sources" / ("starbeacon-" + bundle)
            (source / "bin").mkdir(parents=True)
            (source / "www").mkdir()
            (source / "config").mkdir()
            (source / "README.md").write_text("测试夹具")
            (source / "LICENSE").write_text("隔离的合成项目许可夹具，不作为产品发行许可。")
            (source / "www/index.html").write_text("<html></html>")
            license_text = "隔离的合成依赖许可夹具，不作为第三方许可证明。"
            licenses = [{"name": "fixture-only", "version": "0.0.0", "identifier": "MIT", "text": license_text, "sha256": hashlib.sha256(license_text.encode()).hexdigest()}]
            (source / "www/third-party-licenses.json").write_text(json.dumps(licenses))
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
            self.checksums["archives"].append({"name": archive.name, "sha256": packager.digest(archive), "size": archive.stat().st_size})
        self.save()

    def save(self, value=None):
        (self.root / "checksums.json").write_text(json.dumps(self.checksums if value is None else value))

    def verify(self):
        return release.verify_packages(self.root, VERSION, COMMIT)

    def update_record(self, index):
        record = self.checksums["archives"][index]
        archive = self.root / record["name"]
        record.update(size=archive.stat().st_size, sha256=packager.digest(archive))
        self.save()

    def test_package_files_and_buildinfo_permissions(self):
        self.assertEqual(self.verify(), self.checksums)
        with zipfile.ZipFile(self.root / self.checksums["archives"][0]["name"]) as archive:
            self.assertEqual(stat.S_IMODE(archive.getinfo("starbeacon-platform/bin/starbeacon.buildinfo.txt").external_attr >> 16), 0o644)

    def test_checksums_identity_and_archive_set_rejected(self):
        mutations = (lambda d: d.update(commit="c" * 40), lambda d: d.update(version="v0.2.0"),
                     lambda d: d["archives"].pop(), lambda d: d["archives"].__setitem__(1, d["archives"][0]),
                     lambda d: d["archives"][0].update(name="../../outside.zip"), lambda d: d.update(archives=None),
                     lambda d: d["archives"][0].update(size=True), lambda d: d["archives"][0].update(sha256="bad"),
                     lambda d: d["archives"][0].update(sha256="f" * 64))
        for mutation in mutations:
            changed = copy.deepcopy(self.checksums)
            mutation(changed)
            self.save(changed)
            with self.subTest(data=changed), self.assertRaises(ValueError):
                self.verify()
        self.save()
        (self.root / "unexpected.zip").write_bytes(b"x")
        with self.assertRaises(ValueError):
            self.verify()
        (self.root / "unexpected.zip").unlink()
        (self.root / "checksums.json").unlink()
        with self.assertRaisesRegex(ValueError, "发行清单"):
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
        source = self.root / "sources/starbeacon-platform"
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
            path.unlink()
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
        (source / "link").symlink_to(self.root / "checksums.json")
        with self.assertRaises(ValueError):
            packager.archive(source, self.root / "unsafe.zip", 1_700_000_000)


class ReleaseNotesTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        (self.root / "docs/releases").mkdir(parents=True)
        self.data = {"commit": COMMIT, "version": VERSION, "archives": [{"name": f"starbeacon-{bundle}-{VERSION}-linux-amd64.zip", "sha256": digit * 64, "size": 1} for bundle, digit in (("platform", "1"), ("collector", "2"))]}

    def notes(self, version=VERSION, run_url=RUN_URL):
        return release.release_notes(self.root, {**self.data, "version": version}, version, COMMIT, REPOSITORY, run_url, root=self.root).read_text(encoding="utf-8")

    def test_release_document_links_are_bound_to_commit(self):
        (self.root / f"docs/releases/{VERSION}.md").write_text("# StarBeacon v0.1.0\n\n部署见[工程实现与开发](../工程实现与开发.md)。\n", encoding="utf-8")
        notes = self.notes()
        self.assertIn(f"](https://github.com/{REPOSITORY}/blob/{COMMIT}/docs/工程实现与开发.md)", notes)
        self.assertNotIn("](../", notes)
        self.assertIn(f"来源提交：`{COMMIT}`", notes)
        self.assertIn(f"]({RUN_URL})", notes)
        self.assertIn(f"| starbeacon-platform-{VERSION}-linux-amd64.zip | `{'1' * 64}` |", notes)
        self.assertIn(f"| starbeacon-collector-{VERSION}-linux-amd64.zip | `{'2' * 64}` |", notes)
        self.assertIn("不代表完整产品或生产环境验收", notes)

    def test_default_notes_distinguish_prerelease(self):
        stable = self.notes()
        self.assertTrue(stable.startswith(f"# StarBeacon {VERSION}\n"))
        self.assertIn("正式版本", stable)
        self.assertIn(f"https://github.com/{REPOSITORY}/blob/{COMMIT}/docs/工程实现与开发.md", stable)
        self.assertIn("预发布版本", self.notes("v0.2.0-rc.1"))

    def test_invalid_run_url_and_document_rejected(self):
        for url in ("http://github.com/kkx600/StarBeacon/actions/runs/1", "https://github.com/other/repo/actions/runs/1", f"https://github.com/{REPOSITORY}/actions/runs/0", f"https://github.com/{REPOSITORY}/actions/runs/1/../2", None):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "运行地址"):
                self.notes(run_url=url)
        outside = self.root / "outside.md"
        outside.write_text("外部说明", encoding="utf-8")
        (self.root / f"docs/releases/{VERSION}.md").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "发行说明"):
            self.notes()


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        (self.root / "notes.md").write_text("# 发行说明夹具\n", encoding="utf-8")
        self.created = []

    def publish(self, api, version=VERSION):
        data = {"commit": COMMIT, "version": version, "archives": [{"name": f"starbeacon-{bundle}-{version}-linux-amd64.zip", "sha256": "1" * 64, "size": 1} for bundle in ("platform", "collector")]}
        with patch.object(release, "verify_packages", return_value=data) as verify:
            release.publish(self.root, version, COMMIT, REPOSITORY, api=api, gh=self.created.append)
        verify.assert_called_once_with(self.root, version, COMMIT)

    def test_stable_release_is_created_from_verified_files(self):
        api = FakeGitHub(releases=[{"id": 7, "tag_name": "v0.0.9", "draft": False}])
        self.publish(api)
        self.assertEqual(self.created, [["gh", "release", "create", VERSION,
                                         str(self.root / f"starbeacon-platform-{VERSION}-linux-amd64.zip"),
                                         str(self.root / f"starbeacon-collector-{VERSION}-linux-amd64.zip"),
                                         str(self.root / "checksums.json"), "--repo", REPOSITORY, "--verify-tag",
                                         "--title", f"StarBeacon {VERSION}", "--notes-file", str(self.root / "notes.md")]])
        self.assertFalse([call for call in api.calls if call[0] == "DELETE"])

    def test_prerelease_does_not_take_latest(self):
        self.publish(FakeGitHub(version="v0.2.0-rc.1"), "v0.2.0-rc.1")
        self.assertEqual(self.created[0][-2:], ["--prerelease", "--latest=false"])

    def test_failed_draft_is_replaced_and_published_release_is_kept(self):
        api = FakeGitHub(releases=[{"id": 42, "tag_name": VERSION, "draft": True}])
        self.publish(api)
        self.assertIn(("DELETE", f"repos/{REPOSITORY}/releases/42"), api.calls)
        self.assertEqual(len(self.created), 1)
        for releases in ([{"id": 43, "tag_name": VERSION, "draft": False}], [{"id": True, "tag_name": VERSION, "draft": True}]):
            self.created.clear()
            with self.subTest(releases=releases), self.assertRaises(ValueError):
                self.publish(FakeGitHub(releases=releases))
            self.assertEqual(self.created, [])

    def test_moved_tag_or_missing_notes_stops_before_publishing(self):
        with self.assertRaisesRegex(ValueError, "其他提交"):
            self.publish(FakeGitHub(tag={"type": "commit", "sha": "c" * 40}))
        (self.root / "notes.md").unlink()
        with self.assertRaisesRegex(ValueError, "发行说明"):
            self.publish(FakeGitHub())
        self.assertEqual(self.created, [])


if __name__ == "__main__":
    unittest.main()
