"""使用明确的合成依赖测试发行拒绝边界，不作为真实产品或许可验收。"""
import base64
import copy
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
import package_go_dependencies as dependencies

FIXTURE_MODULE = "example.test/fixture"
FIXTURE_SUM = "h1:" + base64.b64encode(b"f" * 32).decode()


def dependency_fixture(source, metadata, roles):
    """只构造校验器输入；合成 ELF、源码和 SBOM 均不执行。"""
    directory = source / "dependencies"
    directory.mkdir()
    for name, text in {"go-runtime/LICENSE": "运行时许可夹具", "go-runtime/PATENTS": "运行时专利夹具", "notices/example.test/fixture/LICENSE": "MPL-2.0 许可夹具", "notices/example.test/fixture/source.go": "package fixture\n"}.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    linked = {FIXTURE_MODULE: {"version": "v1.0.0", "sum": FIXTURE_SUM}}
    audits = {}
    for role in roles:
        build = f"{role}: go{metadata['go']}\n\tpath\t{dependencies.MODULE}/cmd/{role}\n\tmod\t{dependencies.MODULE}\t(devel)\t\n\tdep\t{FIXTURE_MODULE}\tv1.0.0\t{FIXTURE_SUM}\n\tbuild\tGOOS=linux\n\tbuild\tGOARCH=amd64\n\tbuild\tCGO_ENABLED=0\n"
        (source / "bin" / (role + ".buildinfo.txt")).write_text(build)
        raw_bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                   "metadata": {"tools": [{"name": "cyclonedx-gomod", "version": dependencies.CYCLONEDX}], "component": {"bom-ref": "fixture-main", "properties": [{"name": "cdx:gomod:build:env:" + name, "value": value} for name, value in {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0", "GOVERSION": "go" + metadata["go"]}.items()]}},
                   "components": [{"name": FIXTURE_MODULE, "version": "v1.0.0", "bom-ref": "fixture-module", "hashes": [{"alg": "SHA-256", "content": (b"f" * 32).hex()}]}, {"name": "std", "version": "go" + metadata["go"], "bom-ref": "fixture-runtime"}],
                   "dependencies": [{"ref": "fixture-main", "dependsOn": ["fixture-module", "fixture-runtime"]}, {"ref": "fixture-module", "dependsOn": []}, {"ref": "fixture-runtime", "dependsOn": []}]}
        bom = dependencies.sbom_bind(json.dumps(raw_bom), linked, role, metadata["version"], metadata["commit"], metadata["arch"], metadata["go"], metadata["binaries"][role])
        path = directory / (role + ".cdx.json")
        path.write_text(json.dumps(bom))
        audits[role] = {"modules": linked, "binary": metadata["binaries"][role]["sha256"], "sbom": {"path": path.name, "sha256": dependencies.sha(path.read_bytes())},
                        "packages": {FIXTURE_MODULE: {"module": FIXTURE_MODULE, "inputs": [{"path": "source.go", "sha256": dependencies.sha((directory / "notices/example.test/fixture/source.go").read_bytes())}]}},
                        "licenses": [{"module": FIXTURE_MODULE, "version": "v1.0.0", "identifier": "MPL-2.0", "detection": "go-licenses", "path": "notices/example.test/fixture/LICENSE", "sha256": dependencies.sha((directory / "notices/example.test/fixture/LICENSE").read_bytes()), "source_root": "notices/example.test/fixture", "source_base": "."}]}
    files = [{"path": p.relative_to(directory).as_posix(), "sha256": dependencies.sha(p.read_bytes()), "size": p.stat().st_size} for p in sorted(directory.rglob("*")) if p.is_file()]
    notice = {"schema_version": 1, **{key: metadata[key] for key in ("version", "commit", "os", "arch", "go")}, "tools": {"go-licenses": dependencies.GO_LICENSES, "cyclonedx-gomod": dependencies.CYCLONEDX}, "roles": audits, "files": files}
    path = directory / "go.json"
    path.write_text(json.dumps(notice))
    metadata["go_dependencies"] = {"path": "dependencies/go.json", "sha256": dependencies.sha(path.read_bytes()), "file_count": len(files), "module_counts": {role: 1 for role in roles}}
    return notice


class GoDependencyTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name).resolve()
        (self.root / "bin").mkdir()
        self.role = "starbeacon-agent"
        self.meta = {"version": "v0.1.0", "commit": "a" * 40, "os": "linux", "arch": "amd64", "go": "1.26.8", "binaries": {self.role: {"sha256": "b" * 64, "uncompressed_sha256": "c" * 64}}}
        self.notice = dependency_fixture(self.root, self.meta, [self.role])

    def verify(self):
        names = {p.relative_to(self.root).as_posix() for p in self.root.rglob("*") if p.is_file()}
        return dependencies.verify_bundle(lambda name: (self.root / name).read_bytes(), names, self.meta, [self.role])

    def publish_notice(self):
        path = self.root / "dependencies/go.json"
        path.write_text(json.dumps(self.notice))
        self.meta["go_dependencies"]["sha256"] = dependencies.sha(path.read_bytes())

    def test_complete_fixture_and_actual_buildinfo_binding(self):
        self.assertEqual(self.verify()["roles"][self.role]["modules"], self.notice["roles"][self.role]["modules"])
        path = self.root / "bin" / (self.role + ".buildinfo.txt")
        original = path.read_text()
        for old, replacement in (("go1.26.8", "go1.26.7"), ("GOARCH=amd64", "GOARCH=arm64"), ("CGO_ENABLED=0", "CGO_ENABLED=1"), ("cmd/starbeacon-agent", "cmd/starbeacon"), ("v1.0.0", "v1.0.1")):
            path.write_text(original.replace(old, replacement))
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.verify()
        path.write_text(original + "\t=>\texample.test/local\tv1.0.0\t\n")
        with self.assertRaises(ValueError):
            self.verify()

    def test_dependencies_cannot_be_omitted_or_claim_unrelated_binaries(self):
        initial = copy.deepcopy(self.notice)
        for mutate in (lambda a: a.update(modules={}), lambda a: a.update(binary="d" * 64), lambda a: a.update(licenses=[]), lambda a: a.update(packages={}), lambda a: a["licenses"][0].update(identifier="Unknown"), lambda a: a["licenses"][0].update(version="v2.0.0"), lambda a: a["licenses"][0].update(detection="assumed")):
            self.notice = copy.deepcopy(initial)
            mutate(self.notice["roles"][self.role])
            self.publish_notice()
            with self.assertRaises(ValueError):
                self.verify()

    def test_runtime_sources_and_original_notices_required(self):
        for name in ("go-runtime/LICENSE", "go-runtime/PATENTS", "notices/example.test/fixture/LICENSE", "notices/example.test/fixture/source.go"):
            path = self.root / "dependencies" / name
            content = path.read_bytes()
            path.write_bytes(content + b"changed")
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify()
            path.write_bytes(content)
        # 重新计算目录摘要仍不能掩盖源码与编译输入的差异。
        path = self.root / "dependencies/notices/example.test/fixture/source.go"
        path.write_bytes(b"tampered source")
        record = next(f for f in self.notice["files"] if f["path"].endswith("source.go"))
        record.update(size=path.stat().st_size, sha256=dependencies.sha(path.read_bytes()))
        self.publish_notice()
        with self.assertRaisesRegex(ValueError, "源码"):
            self.verify()

    def test_unlisted_duplicate_and_traversal_files_rejected(self):
        path = self.root / "dependencies/extra.txt"
        path.write_text("未声明文件夹具")
        with self.assertRaises(ValueError):
            self.verify()
        path.unlink()
        original = copy.deepcopy(self.notice)
        for name in ("../escape", "/absolute", "notices//file", "notices\\file", "."):
            self.notice = copy.deepcopy(original)
            self.notice["files"][0]["path"] = name
            self.publish_notice()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify()
        self.notice = copy.deepcopy(original)
        self.notice["files"][1] = copy.deepcopy(self.notice["files"][0])
        self.publish_notice()
        with self.assertRaises(ValueError):
            self.verify()

    def test_sbom_component_graph_and_compressed_program_binding(self):
        role = self.notice["roles"][self.role]
        path = self.root / "dependencies" / role["sbom"]["path"]
        original = json.loads(path.read_bytes())
        for mutate in (lambda b: b["components"].pop(), lambda b: b["components"][0].update(version="v2.0.0"), lambda b: b["components"][0]["hashes"][0].update(content="a" * 64), lambda b: b["metadata"]["component"].update(version="v0.2.0"), lambda b: b["metadata"]["component"]["hashes"][0].update(content="f" * 64), lambda b: b["dependencies"][0]["dependsOn"].append("missing-ref")):
            bom = copy.deepcopy(original)
            mutate(bom)
            path.write_text(json.dumps(bom))
            digest = dependencies.sha(path.read_bytes())
            role["sbom"]["sha256"] = digest
            next(f for f in self.notice["files"] if f["path"] == path.name).update(sha256=digest, size=path.stat().st_size)
            self.publish_notice()
            with self.assertRaises(ValueError):
                self.verify()

    def test_license_exception_requires_exact_module_version_sum_and_text(self):
        module = {"Path": FIXTURE_MODULE, "Version": "v1.0.0", "Sum": FIXTURE_SUM, "Dir": str(self.root)}
        path = self.root / "LICENSE"
        path.write_text("经过摘要绑定的合成许可夹具")
        record = {"module": FIXTURE_MODULE, "version": "v1.0.0", "sum": FIXTURE_SUM, "identifier": "MIT-0", "license": "LICENSE", "sha256": dependencies.sha(path.read_bytes()), "source": "https://example.test/LICENSE", "reference": "https://spdx.org/licenses/MIT-0.html", "reason": "合成边界测试"}
        raw = lambda r: json.dumps({"schema_version": 1, "modules": [r]})
        self.assertEqual(dependencies.verified_exceptions(raw(record), {FIXTURE_MODULE: module})[FIXTURE_MODULE]["identifier"], "MIT-0")
        for key, value in (("version", "v2.0.0"), ("sum", "h1:wrong"), ("sha256", "a" * 64), ("license", "../LICENSE"), ("identifier", "Unknown"), ("source", "http://example.test")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                dependencies.verified_exceptions(raw({**record, key: value}), {FIXTURE_MODULE: module})

    def test_compiler_selection_and_unknown_licenses_fail_closed(self):
        module = {"Path": FIXTURE_MODULE, "Version": "v1.0.0", "Sum": FIXTURE_SUM, "Dir": str(self.root)}
        (self.root / "source.go").write_text("package fixture\n")
        (self.root / "LICENSE").write_text("许可夹具")
        raw = json.dumps({"ImportPath": FIXTURE_MODULE, "Dir": str(self.root), "Module": module, "GoFiles": ["source.go"]})
        linked = {FIXTURE_MODULE: {"version": "v1.0.0", "sum": FIXTURE_SUM}}
        packages, modules = dependencies.compiler_inventory(raw, linked)
        report = f"{FIXTURE_MODULE}\tv1.0.0\tMIT\t{self.root}/LICENSE\thttps://example.test/LICENSE\n"
        self.assertEqual(len(dependencies.license_report(report, packages, modules, {})), 1)
        for value in (report.replace("\tMIT\t", "\tUnknown\t"), report.replace("v1.0.0", "v2.0.0"), report.replace(str(self.root) + "/LICENSE", "/etc/passwd"), report.replace(FIXTURE_MODULE, "example.test/unrelated"), ""):
            with self.assertRaises(ValueError):
                dependencies.license_report(value, packages, modules, {})
        for value in (raw + raw, raw.replace('"source.go"', '"../source.go"'), json.dumps({"ImportPath": FIXTURE_MODULE, "Module": {**module, "Replace": module}})):
            with self.assertRaises(ValueError):
                dependencies.compiler_inventory(value, linked)


if __name__ == "__main__":
    unittest.main()
