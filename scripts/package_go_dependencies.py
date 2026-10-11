#!/usr/bin/env python3
"""用社区工具收集实际 Go 编译依赖，绑定 SBOM、许可原文和需交付的源码。"""
import base64
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import zlib

MODULE = "github.com/kkx600/StarBeacon"
GO_LICENSES = "v2.0.1"
CYCLONEDX = "v1.12.0"
TOOL_SUMS = {"github.com/google/go-licenses/v2": "h1:ti+9bi5o7DKbeeg5eBb/uZTgsaPNoJaLCh93cRcXsW8=", "github.com/CycloneDX/cyclonedx-gomod": "h1:OuFUYNhnjpju7RNArOVPPchFPWNobGfhrHODDPKcgZs="}
ALLOWED_LICENSES = {"Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT", "MIT-0", "MPL-2.0"}
MAX_FILE = 16 * 1024 * 1024


def sha(content):
    return hashlib.sha256(content).hexdigest()


def relative(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("依赖交付路径无效")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value or value == ".":
        raise ValueError("依赖交付路径必须为规范的相对路径")
    return path


def checksum(value):
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise ValueError("依赖交付摘要无效")
    return value


def ordinary(path, limit=MAX_FILE, allow_empty=False):
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file() or not (0 if allow_empty else 1) <= path.stat().st_size <= limit:
        raise ValueError("依赖交付文件缺失、包含链接或体积无效")
    return path.read_bytes()


def contained(path, directory):
    path, directory = pathlib.Path(path), pathlib.Path(directory)
    if not path.is_absolute() or path.resolve() != path or not path.is_relative_to(directory):
        raise ValueError("依赖文件越出已核对的模块目录")
    return path


def documents(raw):
    decoder, offset, result = json.JSONDecoder(), 0, []
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset == len(raw):
            break
        record, offset = decoder.raw_decode(raw, offset)
        if not isinstance(record, dict):
            raise ValueError("Go 依赖目录不是对象")
        result.append(record)
    if not result or len(result) > 10000:
        raise ValueError("Go 依赖目录为空或超限")
    return result


def build_modules(raw, role, go_version, arch):
    lines = raw.splitlines()
    if not lines or lines[0].rsplit(": ", 1)[-1] != "go" + go_version:
        raise ValueError("程序构建信息的 Go 版本不一致")
    result, path, main, settings = {}, None, None, {}
    for line in lines[1:]:
        parts = line.lstrip("\t").split("\t")
        if parts[0] == "=>":
            raise ValueError("发行依赖不接受未经资格核对的模块替换")
        if parts[0] == "path" and len(parts) == 2:
            path = parts[1]
        elif parts[0] == "mod" and len(parts) >= 3:
            main = parts[1]
        elif parts[0] == "dep" and len(parts) == 4:
            name, version, checksum = parts[1:]
            if name in result or not re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", checksum) or not version.startswith("v"):
                raise ValueError("程序依赖身份、版本或 Go 校验和无效")
            result[name] = {"version": version, "sum": checksum}
        elif parts[0] == "build" and len(parts) == 2 and "=" in parts[1]:
            key, value = parts[1].split("=", 1)
            settings[key] = value
    if (path != MODULE + "/cmd/" + role or main != MODULE or not result
        or any(settings.get(k) != v for k, v in {"GOOS": "linux", "GOARCH": arch, "CGO_ENABLED": "0"}.items())):
        raise ValueError("程序身份或编译目标与依赖目录不一致")
    return result


def compiler_inventory(raw, linked):
    packages, modules = {}, {}
    for item in documents(raw):
        name = item.get("ImportPath")
        if not isinstance(name, str) or name in packages or item.get("Error") or item.get("DepsErrors"):
            raise ValueError("编译器依赖包缺失、重复或含错误")
        if item.get("Standard"):
            continue
        mod = item.get("Module")
        if not isinstance(mod, dict) or mod.get("Replace"):
            raise ValueError("编译器依赖缺少模块身份或存在替换")
        if mod.get("Main"):
            if mod.get("Path") != MODULE:
                raise ValueError("主模块身份不一致")
            continue
        identity = {key: mod.get(key) for key in ("Path", "Version", "Sum", "Dir")}
        if (identity["Path"] not in linked or linked[identity["Path"]] != {"version": identity["Version"], "sum": identity["Sum"]}
            or not isinstance(identity["Dir"], str) or not isinstance(item.get("Dir"), str)):
            raise ValueError("编译器与真实程序的依赖身份不一致")
        modules[identity["Path"]] = identity
        directory = contained(item["Dir"], identity["Dir"])
        files = sorted(set(item.get("GoFiles", []) + item.get("SFiles", []) + item.get("SysoFiles", []) + item.get("EmbedFiles", [])))
        inputs = []
        for file in files:
            target = contained(directory / file, identity["Dir"])
            inputs.append({"path": target.relative_to(identity["Dir"]).as_posix(), "sha256": sha(ordinary(target, allow_empty=True))})
        packages[name] = {"module": identity["Path"], "directory": directory, "inputs": inputs}
    if set(modules) != set(linked) or not packages:
        raise ValueError("编译器依赖目录与真实程序存在遗漏")
    return packages, modules


def verified_exceptions(raw, modules):
    value = json.loads(raw)
    if value.get("schema_version") != 1 or not isinstance(value.get("modules"), list):
        raise ValueError("依赖许可例外目录无效")
    result, seen = {}, set()
    for record in value["modules"]:
        name = record.get("module")
        if not isinstance(name, str) or name in seen or record.get("identifier") not in ALLOWED_LICENSES:
            raise ValueError("依赖许可例外重复或标识无效")
        seen.add(name)
        if name not in modules:
            continue
        module = modules[name]
        if (record.get("version") != module["Version"] or record.get("sum") != module["Sum"]
            or not isinstance(record.get("license"), str) or not record.get("source", "").startswith("https://")
            or not record.get("reference", "").startswith("https://") or not record.get("reason")):
            raise ValueError("固定依赖许可例外的身份或来源不一致")
        path = contained(pathlib.Path(module["Dir"]) / record["license"], module["Dir"])
        if sha(ordinary(path)) != record.get("sha256"):
            raise ValueError("固定依赖许可例外的原文摘要不一致")
        result[name] = {**record, "license_path": path}
    return result


def license_report(raw, packages, modules, exceptions):
    records, matched = {}, set()
    for line in raw.splitlines():
        if line == "":
            continue
        parts = line.split("\t")
        if len(parts) != 5:
            raise ValueError("许可工具回执字段不完整")
        name, version, identifier, filename, url = parts
        if name == MODULE or name.startswith(MODULE + "/"):
            if identifier != "Apache-2.0":
                raise ValueError("主模块许可与发行声明不一致")
            continue
        candidates = [key for key in modules if name == key or name.startswith(key + "/")]
        if not candidates or not any(package == name or package.startswith(name + "/") for package in packages):
            raise ValueError("许可工具回执包含未编译的包")
        module = modules[max(candidates, key=len)]
        if version != module["Version"]:
            raise ValueError("许可工具与编译器的模块版本不一致")
        detection = "go-licenses"
        if identifier == "Unknown" and module["Path"] in exceptions:
            special = exceptions[module["Path"]]
            if filename not in ("Unknown", str(special["license_path"])):
                raise ValueError("许可例外不能覆盖模块内其他未知原文")
            identifier, filename, url = special["identifier"], str(special["license_path"]), special["source"]
            detection = "version_and_digest_exception"
        if identifier not in ALLOWED_LICENSES:
            raise ValueError("依赖许可未知或尚未纳入交付核对")
        path = contained(filename, module["Dir"])
        text = ordinary(path)
        if not text.decode("utf-8").strip():
            raise ValueError("依赖许可原文不能为空")
        key = (module["Path"], path.relative_to(module["Dir"]).as_posix(), identifier)
        records[key] = {"module": module["Path"], "version": version, "identifier": identifier, "source_path": key[1], "sha256": sha(text), "detection": detection}
        if identifier == "MPL-2.0":
            records[key]["source_root"] = "notices/" + name
            records[key]["source_base"] = path.parent.relative_to(module["Dir"]).as_posix()
        if url != "Unknown":
            if not url.startswith("https://"):
                raise ValueError("依赖许可来源必须使用 HTTPS")
            if detection == "version_and_digest_exception":
                records[key]["url"] = url
        # 相同原文可能覆盖多个不共享 import 前缀的兄弟包，按源目录边界核对。
        for package, value in packages.items():
            if value["module"] == module["Path"] and value["directory"].is_relative_to(path.parent):
                matched.add(package)
    if matched != set(packages):
        raise ValueError("许可目录没有覆盖全部实际编译依赖")
    return sorted(records.values(), key=lambda r: (r["module"], r["source_path"], r["identifier"]))


def sbom_bind(raw, linked, role, version, commit, arch, go_version, binary, verify_existing=False):
    value = json.loads(raw)
    if value.get("bomFormat") != "CycloneDX" or value.get("specVersion") != "1.6" or value.get("version") != 1:
        raise ValueError("SBOM 格式或规范版本不一致")
    components = value.get("components", [])
    observed, refs, runtime = {}, set(), None
    for component in components:
        name, ref = component.get("name"), component.get("bom-ref")
        if not isinstance(ref, str) or ref in refs:
            raise ValueError("SBOM 组件引用重复或缺失")
        refs.add(ref)
        if name == "std":
            runtime = component.get("version")
            continue
        if name in observed or name not in linked or component.get("version") != linked[name]["version"]:
            raise ValueError("SBOM 存在未打包或版本不一致的依赖")
        expected_hash = base64.b64decode(linked[name]["sum"][3:], validate=True).hex()
        if not any(h.get("alg") == "SHA-256" and h.get("content") == expected_hash for h in component.get("hashes", [])):
            raise ValueError("SBOM 依赖与 Go 校验和不一致")
        observed[name] = component["version"]
    if set(observed) != set(linked) or runtime != "go" + go_version:
        raise ValueError("SBOM 缺少程序依赖或 Go 运行时")
    main = value["metadata"]["component"]
    tools = value["metadata"].get("tools", [])
    if not any(tool.get("name") == "cyclonedx-gomod" and tool.get("version") == CYCLONEDX for tool in tools):
        raise ValueError("SBOM 生成器版本与锁定依赖不一致")
    if not verify_existing:
        # 工具的编译路径会改变自身哈希；发行 SBOM 记录锁定版本，原始工具信息留在构建诊断。
        for tool in tools:
            tool.pop("hashes", None)
    properties = {p["name"]: p["value"] for p in main.get("properties", [])}
    if any(properties.get("cdx:gomod:build:env:" + k) != v for k, v in {"GOOS": "linux", "GOARCH": arch, "CGO_ENABLED": "0", "GOVERSION": "go" + go_version}.items()):
        raise ValueError("SBOM 构建目标不一致")
    old_ref = main["bom-ref"]
    ref = "pkg:golang/" + MODULE + "@" + urllib.parse.quote(version, safe="") + "?goarch=" + arch + "&goos=linux&type=module#cmd/" + role
    if verify_existing:
        if (main.get("name") != role or main.get("version") != version or old_ref != ref or main.get("purl") != ref
            or main.get("hashes") != [{"alg": "SHA-256", "content": binary["sha256"]}]
            or any(properties.get(k) != v for k, v in {"starbeacon:source:commit": commit, "starbeacon:binary:uncompressed_sha256": binary["uncompressed_sha256"], "starbeacon:binary:encoding": "upx"}.items())):
            raise ValueError("SBOM 没有绑定实际版本、提交与压缩程序")
    else:
        main.update({"name": role, "version": version, "bom-ref": ref, "purl": ref, "hashes": [{"alg": "SHA-256", "content": binary["sha256"]}]})
        main.setdefault("properties", []).extend([
            {"name": "starbeacon:source:commit", "value": commit},
            {"name": "starbeacon:binary:uncompressed_sha256", "value": binary["uncompressed_sha256"]},
            {"name": "starbeacon:binary:encoding", "value": "upx"},
        ])
    dependencies = value.get("dependencies", [])
    for dependency in dependencies:
        if dependency.get("ref") == old_ref:
            dependency["ref"] = ref
        dependency["dependsOn"] = [ref if item == old_ref else item for item in dependency.get("dependsOn", [])]
        if dependency.get("ref") not in refs | {ref} or any(item not in refs | {ref} for item in dependency["dependsOn"]):
            raise ValueError("SBOM 依赖图包含失效的组件引用")
    if not any(d.get("ref") == ref for d in dependencies):
        raise ValueError("SBOM 缺少实际程序的依赖图")
    return value


def verify_bundle(read, names, metadata, roles):
    declaration = metadata.get("go_dependencies")
    if (not isinstance(declaration, dict) or declaration.get("path") != "dependencies/go.json"
        or type(declaration.get("file_count")) is not int or not 1 <= declaration["file_count"] <= 8000
        or not isinstance(declaration.get("module_counts"), dict) or set(declaration["module_counts"]) != set(roles)):
        raise ValueError("发行清单缺少 Go 依赖交付记录")
    content = read("dependencies/go.json")
    if len(content) > MAX_FILE or sha(content) != checksum(declaration.get("sha256")):
        raise ValueError("Go 依赖目录与发行清单摘要不一致")
    value = json.loads(content)
    if (type(value.get("schema_version")) is not int or value["schema_version"] != 1
        or any(value.get(k) != metadata[k] for k in ("version", "commit", "os", "arch", "go"))
        or value.get("tools") != {"go-licenses": GO_LICENSES, "cyclonedx-gomod": CYCLONEDX}
        or not isinstance(value.get("roles"), dict) or set(value["roles"]) != set(roles)
        or not isinstance(value.get("files"), list) or len(value["files"]) != declaration["file_count"]):
        raise ValueError("Go 依赖目录的版本、架构、工具或程序集合不一致")
    files = {}
    for item in value["files"]:
        if not isinstance(item, dict):
            raise ValueError("Go 交付文件记录无效")
        path = relative(item.get("path")).as_posix()
        if (path in files or path == "go.json" or type(item.get("size")) is not int or not 0 <= item["size"] <= MAX_FILE):
            raise ValueError("Go 交付文件重复、递归或体积超限")
        raw = read("dependencies/" + path)
        if len(raw) != item["size"] or sha(raw) != checksum(item.get("sha256")):
            raise ValueError("Go 交付文件的原文与目录摘要不一致")
        files[path] = item
    actual = {name.removeprefix("dependencies/") for name in names if name.startswith("dependencies/") and name != "dependencies/go.json"}
    if set(files) != actual or not {"go-runtime/LICENSE", "go-runtime/PATENTS"} <= set(files):
        raise ValueError("Go 依赖交付遗漏文件、包含未声明文件或缺少运行时许可")
    for name in ("go-runtime/LICENSE", "go-runtime/PATENTS"):
        if not read("dependencies/" + name).decode("utf-8").strip():
            raise ValueError("Go 运行时许可不能为空")
    for role in roles:
        audit = value["roles"][role]
        linked = build_modules(read("bin/" + role + ".buildinfo.txt").decode(), role, metadata["go"], metadata["arch"])
        if (not isinstance(audit, dict) or audit.get("modules") != linked or audit.get("binary") != metadata["binaries"][role]["sha256"]
            or type(declaration["module_counts"][role]) is not int or declaration["module_counts"][role] != len(linked)):
            raise ValueError("Go 依赖目录未覆盖实际程序的全部模块")
        sbom = audit.get("sbom")
        if not isinstance(sbom, dict) or sbom.get("path") != role + ".cdx.json" or sbom["path"] not in files or checksum(sbom.get("sha256")) != files[sbom["path"]]["sha256"]:
            raise ValueError("Go 程序 SBOM 缺失或摘要不一致")
        sbom_bind(read("dependencies/" + sbom["path"]), linked, role, metadata["version"], metadata["commit"], metadata["arch"], metadata["go"], metadata["binaries"][role], True)
        licenses = audit.get("licenses")
        packages = audit.get("packages")
        if not isinstance(licenses, list) or not licenses or not isinstance(packages, dict) or not packages:
            raise ValueError("Go 依赖缺少许可或编译包目录")
        covered, covered_sources = set(), set()
        for entry in licenses:
            if (not isinstance(entry, dict) or entry.get("module") not in linked or entry.get("version") != linked[entry["module"]]["version"]
                or entry.get("identifier") not in ALLOWED_LICENSES or entry.get("detection") not in ("go-licenses", "version_and_digest_exception")):
                raise ValueError("Go 依赖许可身份或识别依据无效")
            path = relative(entry.get("path")).as_posix()
            if path not in files or checksum(entry.get("sha256")) != files[path]["sha256"] or not read("dependencies/" + path).decode("utf-8").strip():
                raise ValueError("Go 依赖许可原文缺失或摘要不一致")
            covered.add(entry["module"])
            if entry["identifier"] == "MPL-2.0":
                source_root = relative(entry.get("source_root"))
                base = entry.get("source_base")
                if base != ".":
                    relative(base)
                for name, package in packages.items():
                    if package.get("module") != entry["module"]:
                        continue
                    for item in package.get("inputs", []):
                        original = relative(item.get("path"))
                        if original.is_relative_to(pathlib.PurePosixPath(base)):
                            exported = (source_root / original.relative_to(base)).as_posix()
                            if exported not in files or files[exported]["sha256"] != checksum(item.get("sha256")):
                                raise ValueError("需交付的依赖源码缺失或与编译输入不一致")
                            covered_sources.add(name)
        if covered != set(linked):
            raise ValueError("Go 程序的依赖许可目录不完整")
        package_modules = set()
        for name, package in packages.items():
            if (not isinstance(name, str) or not isinstance(package, dict) or package.get("module") not in linked
                or not name.startswith(package["module"] + "/") and name != package["module"]
                or not isinstance(package.get("inputs"), list) or not package["inputs"]):
                raise ValueError("Go 编译包或源码输入目录无效")
            package_modules.add(package["module"])
            if any(e["identifier"] == "MPL-2.0" and e["module"] == package["module"] for e in licenses) and name not in covered_sources:
                raise ValueError("需交付的编译依赖包没有对应源码")
        if package_modules != set(linked):
            raise ValueError("Go 编译包目录遗漏模块")
    return value


def execute(arguments, root, environment, log):
    try:
        result = subprocess.run(arguments, cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    except subprocess.TimeoutExpired as error:
        log.write_bytes(error.stderr or b"")
        log.with_suffix(".stdout").write_bytes(error.stdout or b"")
        raise
    log.write_bytes(result.stderr)
    log.with_suffix(".stdout").write_bytes(result.stdout)
    if result.returncode:
        raise ValueError("依赖工具执行失败；原始诊断已保留")
    return result.stdout.decode("utf-8")


def sbom_source(root, target, commit_file, commit):
    raw = ordinary(commit_file, 1024 * 1024)
    encoded = b"commit " + str(len(raw)).encode("ascii") + b"\0" + raw
    if re.fullmatch(r"[a-f0-9]{40}", commit) is None or hashlib.sha1(encoded).hexdigest() != commit:
        raise ValueError("SBOM 的真实 Git 提交对象与发行来源不一致")
    target.mkdir()
    # 只复制构建镜像明确包含的源码；提交对象仅供上游工具识别版本，不作为源码资格。
    for name in ("cmd", "internal", "migrations", "api/sensor"):
        origin = root / name
        if origin.is_symlink() or not origin.is_dir() or any(p.is_symlink() for p in origin.rglob("*")):
            raise ValueError("SBOM 源码目录缺失或包含链接")
        shutil.copytree(origin, target / name)
    for name in ("go.mod", "go.sum", "LICENSE"):
        ordinary(root / name)
        shutil.copyfile(root / name, target / name)
    git = target / ".git"
    objects = git / "objects" / commit[:2]
    objects.mkdir(parents=True)
    (git / "refs" / "tags").mkdir(parents=True)
    (git / "HEAD").write_text(commit + "\n", encoding="ascii")
    (git / "config").write_text("[core]\nrepositoryformatversion = 0\nbare = false\n", encoding="ascii")
    (objects / commit[2:]).write_bytes(zlib.compress(encoded))
    return target


def collect(root, source, roles, metadata, environment, licenses_tool, sbom_tool, diagnostics, commit_file):
    root, source = pathlib.Path(root), pathlib.Path(source)
    directory = source / "dependencies"
    directory.mkdir()
    target = directory / "notices"
    audits, records = {}, {}
    template = root / "licenses/go/report.tpl"
    with tempfile.TemporaryDirectory(prefix="starbeacon-notices-") as build_scratch:
        scratch = pathlib.Path(diagnostics)
        scratch.mkdir(parents=True)
        sbom_root = sbom_source(root, pathlib.Path(build_scratch) / "module", commit_file, metadata["commit"])
        toolchain = json.loads(execute(["go", "env", "-json", "GOROOT", "GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED"], root, environment, scratch / "toolchain.log"))
        if (any(toolchain.get(key) != value for key, value in {"GOVERSION": "go" + metadata["go"], "GOOS": "linux", "GOARCH": metadata["arch"], "CGO_ENABLED": "0"}.items())
            or not isinstance(toolchain.get("GOROOT"), str) or not pathlib.Path(toolchain["GOROOT"]).is_absolute()):
            raise ValueError("依赖工具的 Go 工具链或编译目标不一致")
        # 跨系统编译的工具可能带有构建机路径，必须与实际编译器共享标准库目录。
        goroot = pathlib.Path(toolchain["GOROOT"]).resolve(strict=True)
        ordinary(goroot / "LICENSE")
        ordinary(goroot / "PATENTS")
        environment = dict(environment, GOROOT=str(goroot))
        for tool, name, expected in ((licenses_tool, "github.com/google/go-licenses/v2", GO_LICENSES), (sbom_tool, "github.com/CycloneDX/cyclonedx-gomod", CYCLONEDX)):
            output = execute(["go", "version", "-m", tool], root, environment, scratch / (name.rsplit("/", 1)[-1] + ".log"))
            if not any(line == "\tmod\t" + name + "\t" + expected + "\t" + TOOL_SUMS[name] for line in output.splitlines()):
                raise ValueError("依赖工具未使用锁定的上游模块版本")
        ignored, modules_all = set(), {}
        for role in roles:
            linked = build_modules((source / "bin" / (role + ".buildinfo.txt")).read_text(), role, metadata["go"], metadata["arch"])
            raw = execute(["go", "list", "-deps", "-json", "./cmd/" + role], root, environment, scratch / (role + "-compiler.log"))
            packages, modules = compiler_inventory(raw, linked)
            exceptions = verified_exceptions(ordinary(root / "licenses/go/exceptions.json"), modules)
            report = execute([licenses_tool, "report", "--template", str(template), "./cmd/" + role], root, environment, scratch / (role + "-license.log"))
            licenses = license_report(report, packages, modules, exceptions)
            for special in exceptions:
                ignored.add(special + "/")
            modules_all.update(modules)
            for entry in licenses:
                path = "notices/" + entry["module"] + "/" + entry["source_path"]
                entry["path"] = path
                records[(entry["module"], entry["source_path"], entry["identifier"])] = entry
            raw = execute([sbom_tool, "app", "-json", "-std", "-licenses", "-noserial", "-notimestamp", "-output-version", "1.6", "-main", "cmd/" + role, str(sbom_root)], sbom_root, environment, scratch / (role + "-sbom.log"))
            bom = sbom_bind(raw, linked, role, metadata["version"], metadata["commit"], metadata["arch"], metadata["go"], metadata["binaries"][role])
            path = directory / (role + ".cdx.json")
            path.write_text(json.dumps(bom, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
            audits[role] = {"modules": linked, "packages": {name: {"module": item["module"], "inputs": item["inputs"]} for name, item in sorted(packages.items())}, "licenses": licenses, "sbom": {"path": path.name, "sha256": sha(path.read_bytes())}, "binary": metadata["binaries"][role]["sha256"]}
        command = [licenses_tool, "save", "--save_path", str(target)]
        if ignored:
            command += ["--ignore", ",".join(sorted(ignored))]
        execute(command + ["./cmd/" + role for role in roles], root, environment, scratch / "notices-save.log")
        # 已核对的例外不交给分类器猜测；原文仍按实际模块身份装入目录。
        for entry in records.values():
            output = directory / entry["path"]
            if output.exists():
                if sha(ordinary(output)) != entry["sha256"]:
                    raise ValueError("导出的依赖许可与编译来源不一致")
            else:
                output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(contained(pathlib.Path(modules_all[entry["module"]]["Dir"]) / entry["source_path"], modules_all[entry["module"]]["Dir"]), output)
        runtime = directory / "go-runtime"
        runtime.mkdir()
        for name in ("LICENSE", "PATENTS"):
            ordinary(goroot / name)
            shutil.copyfile(goroot / name, runtime / name)
    files = []
    for path in sorted(directory.rglob("*")):
        if path.is_dir():
            continue
        content = ordinary(path, allow_empty=True)
        files.append({"path": path.relative_to(directory).as_posix(), "sha256": sha(content), "size": len(content)})
    if not 1 <= len(files) <= 8000:
        raise ValueError("依赖交付文件数量超限")
    # 有源码交付要求的许可必须附带实际编译文件；只有 LICENSE 不足以通过。
    for audit in audits.values():
        for entry in audit["licenses"]:
            if entry["identifier"] != "MPL-2.0":
                continue
            for package in audit["packages"].values():
                if package["module"] != entry["module"]:
                    continue
                for item in package["inputs"]:
                    path = pathlib.PurePosixPath(item["path"])
                    base = pathlib.PurePosixPath(entry["source_base"])
                    if path.is_relative_to(base):
                        exported = directory / entry["source_root"] / path.relative_to(base)
                        if sha(ordinary(exported, allow_empty=True)) != item["sha256"]:
                            raise ValueError("需交付的依赖源码与实际编译输入不一致")
    notice = {"schema_version": 1, "version": metadata["version"], "commit": metadata["commit"], "os": "linux", "arch": metadata["arch"], "go": metadata["go"], "tools": {"go-licenses": GO_LICENSES, "cyclonedx-gomod": CYCLONEDX}, "roles": audits, "files": files}
    path = directory / "go.json"
    path.write_text(json.dumps(notice, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    return {"path": "dependencies/go.json", "sha256": sha(path.read_bytes()), "file_count": len(files), "module_counts": {role: len(value["modules"]) for role, value in audits.items()}}
