#!/usr/bin/env python3
"""核对需求、实现清单、HTTP 契约和工程路由，生成可追溯的功能状态文档。"""
import argparse
import collections
import json
import pathlib
import re
import sys
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUTPUT = pathlib.Path("docs/功能实现与验收状态.md")
METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
DOMAINS = {"DAT": "数据接入与质量", "AST": "资产与网络关系", "EXP": "风险与暴露治理", "DET": "检测与狩猎", "TI": "威胁情报", "SRH": "检索与证据", "INC": "案件与协作", "RSP": "决策与响应", "AI": "模型与智能分析", "VIS": "态势与展示", "OPS": "运维与集成", "GOV": "身份与治理", "NET": "捕获与检测质量", "FIL": "文件分析"}
STATES = {"partial": "部分实现", "missing": "待实现", "implemented": "实现待验收"}


def load(root, path):
    return json.loads((root / path).read_text())


def checked_file(root, value):
    path = pathlib.PurePosixPath(value)
    if not isinstance(value, str) or path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ValueError(f"实现引用路径无效：{value}")
    target = root / path
    if target.is_symlink() or not target.resolve().is_relative_to(root.resolve()) or not target.is_file():
        raise ValueError(f"实现引用文件不存在或越界：{value}")


def validate_inventory(root, registry, inventory):
    if registry.get("schema_version") != 1 or inventory.get("schema_version") != 1:
        raise ValueError("需求与实现清单版本无效")
    expected = [item["id"] for item in registry["requirements"]]
    if len(expected) != 107 or len(set(expected)) != len(expected):
        raise ValueError("正式需求目录必须恰好包含 107 个独立 ID")
    rows = inventory["requirements"]
    actual = [item["id"] for item in rows]
    if collections.Counter(actual) != collections.Counter(expected):
        raise ValueError("实现清单与 107 项需求不一致或存在重复")
    capabilities = inventory["capabilities"]
    cap_ids = [item["id"] for item in capabilities]
    if len(set(cap_ids)) != len(cap_ids):
        raise ValueError("实现能力标识重复")
    for cap in capabilities:
        for field in ("code", "tests"):
            if not cap.get(field):
                raise ValueError(f"能力缺少代码或测试引用：{cap['id']}")
            for value in cap[field]:
                checked_file(root, value)
    for item in rows:
        if item.get("state") not in STATES or item.get("acceptance") != "pending":
            raise ValueError("实现清单不能冒充功能验收报告；通过状态须由真实验收门禁签认")
        if any(cap not in cap_ids for cap in item["capabilities"]):
            raise ValueError(f"需求引用未登记能力：{item['id']}")
        if item["state"] == "missing" and (item["implemented"] or item["capabilities"]):
            raise ValueError(f"待实现需求包含误导性实现标记：{item['id']}")
        if item["state"] != "missing" and (not item["implemented"] or not item["capabilities"]):
            raise ValueError(f"实现需求缺少实际能力和行为：{item['id']}")
        if (item["state"] == "implemented") != (not item["remaining"]):
            raise ValueError(f"完整实现与缺口状态矛盾：{item['id']}")
        for field in ("implemented", "remaining"):
            if not isinstance(item[field], list) or any(not isinstance(text, str) or not text.strip() for text in item[field]):
                raise ValueError(f"需求描述无效：{item['id']}")
    matrix = (root / "docs/功能覆盖与验收矩阵.md").read_text()
    matrix_rows = {}
    for line in matrix.splitlines():
        if re.match(r"\| SB-[A-Z]+-\d{3} \|", line):
            cells = [cell.strip() for cell in line.split("|")[1:-1]]
            if cells[0] in matrix_rows:
                raise ValueError("目标验收矩阵中需求重复")
            matrix_rows[cells[0]] = cells
    if set(matrix_rows) != set(expected):
        raise ValueError("目标矩阵与需求注册表存在遗漏")
    for item in registry["requirements"]:
        cells = matrix_rows[item["id"]]
        if cells[1] != item["name"] or cells[-1] != item["acceptance"]:
            raise ValueError(f"目标矩阵与验收契约文字偏移：{item['id']}")


def registered_operations(root, role):
    paths = list((root / "internal/platform").glob("*.go")) if role == "platform" else [root / "internal/agent/localapi.go", root / "internal/agent/replay_samples.go", root / "internal/agent/packet_localapi.go"]
    prefix = "/api/v1" if role == "platform" else "/api/local/v1"
    source = "\n".join(path.read_text() for path in paths if not path.name.endswith("_test.go"))
    result = set(re.findall(r'\.HandleFunc\("((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) /api/[^"\s]+)"', source))
    if not re.search(r'\.Register\(m,\s*"' + re.escape(prefix) + r'"\)', source):
        raise ValueError(f"无法确认 {role} 身份路由注册")
    auth = (root / "internal/httpapi/server.go").read_text()
    for method, suffix in re.findall(r'\.HandleFunc\("(GET|POST) "\+prefix\+"(/auth/[^"\s]+)"', auth):
        result.add(method + " " + prefix + suffix)
    return result


def validate_refs(document):
    def visit(value):
        if isinstance(value, dict):
            if "$ref" in value:
                ref = value["$ref"]
                if not ref.startswith("#/"):
                    raise ValueError("当前 OpenAPI 只允许本地契约引用")
                target = document
                try:
                    for part in ref[2:].split("/"):
                        target = target[part.replace("~1", "/").replace("~0", "~")]
                except (KeyError, TypeError):
                    raise ValueError(f"OpenAPI 引用不存在：{ref}") from None
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(document)


def validate_api(root, role, document):
    validate_refs(document)
    actual = registered_operations(root, role)
    documented = {method.upper() + " " + path for path, item in document["paths"].items() for method in item if method in METHODS}
    if actual != documented:
        raise ValueError(f"{role} HTTP 契约偏移；漏写：{sorted(actual-documented)}；未注册：{sorted(documented-actual)}")
    return documented


def platform_navigation_routes(root):
    manifest = load(root, "web/packages/shared/src/navigation.json")
    if manifest.get("schema_version") != 1:
        raise ValueError("导航目录版本无效")
    groups, workspaces, screens = manifest["groups"], manifest["workspaces"], manifest["screens"]
    for rows in (groups, workspaces, screens):
        if not rows or len({row["id"] for row in rows}) != len(rows):
            raise ValueError("导航目录为空或标识重复")
    if any(workspace["group"] not in {group["id"] for group in groups} for workspace in workspaces):
        raise ValueError("工作区缺少有效业务分组")
    if any(screen["workspace"] not in {workspace["id"] for workspace in workspaces} for screen in screens):
        raise ValueError("功能页面缺少有效工作区")
    paths = [screen["path"] for screen in screens]
    if len(set(paths)) != len(paths):
        raise ValueError("功能页面路径重复")
    if any(path.startswith(("/assets/", "/api/")) for path in paths):
        raise ValueError("业务路由占用了静态资源或 API 命名空间")
    for workspace in workspaces:
        if not any(screen["workspace"] == workspace["id"] for screen in screens):
            paths.append("/" + manifest.get("group_paths", {}).get(workspace["group"], workspace["group"]) + "/" + workspace["id"])
    paths += ["/" + key for key in manifest["legacy_modules"]]
    if any(not re.fullmatch(r"/[a-z0-9/-]+", path) or "//" in path for path in paths):
        raise ValueError("导航路径格式无效")
    # 目录父级同样可直接访问并重定向；不得仅检查叶子而遗漏刷新入口。
    return {"/" + "/".join(path.strip("/").split("/")[:index]) for path in paths for index in range(1, len(path.strip("/").split("/")) + 1)}


def _collector_route_tokens(source):
    """只识别受控静态配置的词法单元，不执行源码或依赖前端运行环境。"""
    if not isinstance(source, str) or len(source.encode("utf-8")) > 512 * 1024:
        raise ValueError("采集器路由源码无效或超过静态核对预算")
    tokens, offset = [], 0
    while offset < len(source):
        char = source[offset]
        if char.isspace():
            offset += 1
            continue
        if source.startswith("//", offset):
            ends = [index for end in "\r\n\u2028\u2029" if (index := source.find(end, offset + 2)) >= 0]
            offset = min(ends) + 1 if ends else len(source)
            continue
        if source.startswith("/*", offset):
            end = source.find("*/", offset + 2)
            if end < 0:
                raise ValueError("采集器路由包含未结束的注释")
            offset = end + 2
            continue
        start = offset
        if char in "\"'":
            quote = char
            offset += 1
            while offset < len(source) and source[offset] != quote:
                if source[offset] in "\r\n\u2028\u2029":
                    raise ValueError("采集器路由包含无法核对的字符串换行")
                if source[offset] == "\\":
                    if offset + 1 >= len(source) or source[offset + 1] in "\r\n\u2028\u2029":
                        raise ValueError("采集器路由字符串转义不完整")
                    offset += 1
                offset += 1
            if offset >= len(source):
                raise ValueError("采集器路由字符串未结束")
            offset += 1
            tokens.append(("string", source[start + 1:offset - 1], start, offset))
        elif char.isascii() and (char.isalpha() or char in "_$"):
            offset += 1
            while offset < len(source) and source[offset].isascii() and (source[offset].isalnum() or source[offset] in "_$"):
                offset += 1
            tokens.append(("name", source[start:offset], start, offset))
        elif source.startswith("...", offset):
            offset += 3
            tokens.append(("symbol", "...", start, offset))
        elif source.startswith("=>", offset):
            offset += 2
            tokens.append(("symbol", "=>", start, offset))
        elif char in "{}[]():,;.=<>!?&|+-*%" or char.isascii() and char.isdigit():
            offset += 1
            tokens.append(("symbol", char, start, offset))
        else:
            raise ValueError("采集器路由包含无法静态核对的语法")
        if len(tokens) > 30000:
            raise ValueError("采集器路由词法单元超过核对预算")
    return tokens


def _collector_token_is(tokens, index, kind, value):
    return index < len(tokens) and tokens[index][:2] == (kind, value)


def _collector_static_object(tokens, start, shorthand=()):
    """按括号配对切分顶层属性，嵌套元数据和重定向内容不作为路由。"""
    if not _collector_token_is(tokens, start, "symbol", "{"):
        raise ValueError("采集器路由必须使用静态对象")
    fields, offset = {}, start + 1
    pairs = {"(": ")", "[": "]", "{": "}"}
    while offset < len(tokens) and not _collector_token_is(tokens, offset, "symbol", "}"):
        key = tokens[offset]
        if key[0] not in ("name", "string") or "\\" in key[1] or key[1] in fields:
            raise ValueError("采集器路由属性重复或不能静态确认")
        if not _collector_token_is(tokens, offset + 1, "symbol", ":"):
            if key[0] == "name" and key[1] in shorthand and any(_collector_token_is(tokens, offset + 1, "symbol", end) for end in (",", "}")):
                fields[key[1]] = [key]
                offset += 1
                if _collector_token_is(tokens, offset, "symbol", ","):
                    offset += 1
                continue
            raise ValueError("采集器路由不接受展开、计算属性或未许可的简写属性")
        offset += 2
        begin, stack = offset, []
        while offset < len(tokens):
            value = tokens[offset][1]
            if tokens[offset][0] != "string":
                if not stack and value in (",", "}"):
                    break
                if value in pairs:
                    stack.append(pairs[value])
                    if len(stack) > 128:
                        raise ValueError("采集器路由属性嵌套超过核对预算")
                elif value in pairs.values():
                    if not stack or stack.pop() != value:
                        raise ValueError("采集器路由括号不匹配")
            offset += 1
        if offset == begin or stack:
            raise ValueError("采集器路由属性为空或未结束")
        fields[key[1]] = tokens[begin:offset]
        if _collector_token_is(tokens, offset, "symbol", ","):
            offset += 1
        elif not _collector_token_is(tokens, offset, "symbol", "}"):
            raise ValueError("采集器路由对象未结束")
    if offset >= len(tokens):
        raise ValueError("采集器路由对象未结束")
    return fields, offset + 1


def collector_route_paths(source):
    """提取受控 collectorRoutes 静态树；未知结构失败，真实交互另由 Router 测试验收。"""
    tokens = _collector_route_tokens(source)
    syntax = [token[:2] for token in tokens]
    pairs, stack, depths = {}, [], []
    closing = {"(": ")", "[": "]", "{": "}"}
    for index, (kind, value, _, _) in enumerate(tokens):
        depths.append(len(stack))
        if kind != "symbol":
            continue
        if value in closing:
            stack.append((value, index))
            if len(stack) > 128:
                raise ValueError("采集器路由源码嵌套超过静态核对预算")
        elif value in closing.values():
            if not stack or closing[stack[-1][0]] != value:
                raise ValueError("采集器路由源码括号不匹配")
            pairs[stack.pop()[1]] = index
    if stack:
        raise ValueError("采集器路由源码括号未结束")
    declarations = [index for index in range(len(tokens) - 2)
                    if syntax[index:index + 3] == [("name", "function"), ("name", "collectorRoutes"), ("symbol", "(")]]
    if (len(declarations) != 1 or syntax.count(("name", "collectorRoutes")) != 2
            or depths[declarations[0]] != 0 or declarations[0] and syntax[declarations[0] - 1] in (("name", "async"), ("name", "declare"), ("name", "default"))):
        raise ValueError("采集器必须声明并直接注册唯一的 collectorRoutes 静态工厂")
    offset = declarations[0] + 3
    if not _collector_token_is(tokens, offset, "symbol", ")"):
        raise ValueError("采集器路由工厂不能依赖动态参数")
    offset += 1
    if _collector_token_is(tokens, offset, "symbol", ":"):
        if syntax[offset:offset + 5] != [("symbol", ":"), ("name", "RouteRecordRaw"), ("symbol", "["), ("symbol", "]"), ("symbol", "{")]:
            raise ValueError("采集器路由工厂返回类型无法确认")
        offset += 4
    if syntax[offset:offset + 2] != [("symbol", "{"), ("name", "return")]:
        raise ValueError("采集器路由工厂只能直接返回静态数组")
    body = offset
    offset += 2
    if offset >= len(tokens) or any(char in source[tokens[offset - 1][3]:tokens[offset][2]] for char in "\r\n\u2028\u2029"):
        raise ValueError("采集器路由 return 不能通过自动分号变为未返回数组")

    paths, names, catchalls = set(), set(), []
    allowed = {"path", "component", "components", "redirect", "meta", "props", "name", "beforeEnter", "sensitive", "strict", "end", "children"}

    def route_array(items, start, parent="", depth=0):
        if depth > 16 or not _collector_token_is(items, start, "symbol", "["):
            raise ValueError("采集器 children 必须为有界静态数组")
        index = start + 1
        while index < len(items) and not _collector_token_is(items, index, "symbol", "]"):
            fields, index = _collector_static_object(items, index)
            if set(fields) - allowed or "path" not in fields:
                raise ValueError("采集器路由包含未知属性或缺少明确路径")
            if "name" in fields:
                name = fields["name"]
                if len(name) != 1 or name[0][0] != "string" or not name[0][1] or "\\" in name[0][1] or name[0][1] in names:
                    raise ValueError("采集器路由名称动态、无效或重复，无法确认实际注册范围")
                names.add(name[0][1])
            path_value = fields["path"]
            if len(path_value) != 1 or path_value[0][0] != "string":
                raise ValueError("采集器路由路径必须为单一字面量")
            path = path_value[0][1]
            if path == "/:pathMatch(.*)*":
                if depth or "component" not in fields or "redirect" in fields or "children" in fields:
                    raise ValueError("采集器必须提供独立的全局未知页面边界")
                catchalls.append(path)
            else:
                if (not path or len(path) > 1024 or "\\" in path or path != "/" and not re.fullmatch(r"/?[a-z0-9-]+(?:/[a-z0-9-]+)*", path)
                        or not parent and not path.startswith("/")):
                    raise ValueError("采集器路由路径包含非法或动态段")
                resolved = path if path.startswith("/") else parent.rstrip("/") + "/" + path
                if (len(resolved) > 1024 or resolved in paths or resolved == "/invalid-page"
                        or any(resolved == prefix or resolved.startswith(prefix + "/") for prefix in ("/api", "/assets"))):
                    raise ValueError("采集器路由路径重复、占用保留范围或覆盖未知页面探针")
                if not {"component", "components", "redirect"}.intersection(fields):
                    raise ValueError("采集器路由必须具有实际页面或重定向")
                paths.add(resolved)
                if len(paths) > 4096:
                    raise ValueError("采集器路由数量超过静态核对预算")
                if "children" in fields and route_array(fields["children"], 0, resolved, depth + 1) != len(fields["children"]):
                    raise ValueError("采集器 children 不接受动态拼接或变换")
            if _collector_token_is(items, index, "symbol", ","):
                index += 1
            elif not _collector_token_is(items, index, "symbol", "]"):
                raise ValueError("采集器路由数组未结束")
        if index >= len(items):
            raise ValueError("采集器路由数组未结束")
        return index + 1

    end = route_array(tokens, offset)
    if _collector_token_is(tokens, end, "symbol", ";"):
        end += 1
    if end != pairs[body] or len(catchalls) != 1 or not {"/", "/login", "/access-denied"}.issubset(paths):
        raise ValueError("采集器路由工厂或根、登录、权限、未知页面边界不完整")
    calls = [index for index in range(len(tokens) - 1) if syntax[index:index + 2] == [("name", "createRouter"), ("symbol", "(")]]
    if (len(calls) != 1 or any(kind in ("name", "string") and value in ("addRoute", "removeRoute", "clearRoutes") for kind, value, _, _ in tokens)
            or any(syntax[index:index + 2] == [("symbol", "."), ("name", "routes")] or syntax[index:index + 3] == [("symbol", "["), ("string", "routes"), ("symbol", "]")] for index in range(len(tokens)))):
        raise ValueError("采集器存在无法静态确认的路由注册或变更")
    options, after = _collector_static_object(tokens, calls[0] + 2, shorthand={"history"})
    if set(options) - {"history", "routes", "scrollBehavior", "parseQuery", "stringifyQuery", "linkActiveClass", "linkExactActiveClass", "strict", "sensitive", "end"} or "history" not in options:
        raise ValueError("采集器 createRouter 包含未知配置或缺少 history")
    route_call = [(token[0], token[1]) for token in options.get("routes", [])]
    if route_call != [("name", "collectorRoutes"), ("symbol", "("), ("symbol", ")")] or not _collector_token_is(tokens, after, "symbol", ")"):
        raise ValueError("采集器 createRouter 必须直接注册已核对的静态树")
    # 路由实例只用于守卫和返回；实例转交、计算成员和重赋值无法由静态树证明。
    call = calls[0]
    if call < 3 or syntax[call - 3] != ("name", "const") or tokens[call - 2][0] != "name" or syntax[call - 1] != ("symbol", "="):
        raise ValueError("采集器 createRouter 必须直接初始化独立 const 实例")
    binding, declaration = tokens[call - 2][1], call - 2
    scopes = [begin for begin, finish in pairs.items() if tokens[begin][:2] == ("symbol", "{") and begin < call < finish]
    begin = max(scopes) if scopes else -1
    finish = pairs[begin] if scopes else len(tokens)
    for index in range(begin + 1, finish):
        if syntax[index] != ("name", binding) or index == declaration:
            continue
        guard = (syntax[index + 1:index + 2] == [("symbol", ".")]
                 and index + 3 < len(tokens) and tokens[index + 2][0] == "name"
                 and tokens[index + 2][1] in {"beforeEach", "beforeResolve", "afterEach", "onError", "isReady"}
                 and syntax[index + 3] == ("symbol", "("))
        returned = (index > 0 and syntax[index - 1] == ("name", "return")
                    and index + 1 < len(tokens) and syntax[index + 1] in (("symbol", ";"), ("symbol", "}")))
        if not guard and not returned:
            raise ValueError("采集器路由实例存在无法静态确认的转交或变更")
    return paths


def collector_navigation_routes(root):
    return collector_route_paths((root / "web/collector/src/router.ts").read_text())


def validate_routes(root, routes, inventory):
    for role in ("platform", "collector"):
        source = (root / f"web/{role}/src/router.ts").read_text()
        declared = collector_route_paths(source) if role == "collector" else set(re.findall(r"path:\s*['\"]([^'\"]+)['\"]", source)) - {"/", "/:pathMatch(.*)*"}
        if role == "platform" and "...platformRoutes()" in source:
            declared |= platform_navigation_routes(root)
        listed = routes[role]
        if len(set(listed)) != len(listed) or "/invalid-page" not in listed:
            raise ValueError(f"{role} 验收路由重复或缺少访问边界")
        bases = set()
        for route in listed:
            parsed = urllib.parse.urlsplit(route)
            if parsed.scheme or parsed.netloc or parsed.fragment or not route.startswith("/"):
                raise ValueError(f"{role} 验收路由格式无效")
            if parsed.path != "/invalid-page":
                bases.add(parsed.path)
        if bases != declared:
            raise ValueError(f"{role} 工程路由未完整列入验收：{sorted(declared-bases)}；未实现：{sorted(bases-declared)}")
    for cap in inventory["capabilities"]:
        for page in cap["pages"]:
            role, route = page.split(":", 1)
            if role not in routes or route not in routes[role]:
                raise ValueError(f"能力页面未列入验收路由：{page}")


def direct_modules(root):
    text = (root / "go.mod").read_text()
    return re.findall(r"(?m)^\s*([^\s]+) (v[^\s]+)$", text)


def cell(value):
    return value.replace("|", "／").replace("\n", " ")


def render(root, registry, inventory, api, routes):
    by_id = {item["id"]: item for item in inventory["requirements"]}
    counts = collections.Counter(item["state"] for item in by_id.values())
    lines = ["# 星烽 StarBeacon 功能实现与验收状态", "", f"核对日期：{inventory['review_date']}。本表以实际代码、HTTP 契约、工程页面和测试入口为依据；覆盖 [107 项正式需求](功能覆盖与验收矩阵.md)。当前 **{counts['partial']} 项部分实现、{counts['missing']} 项待实现、{counts['implemented']} 项完整实现待验收**，全部复合需求仍未取得完整验收记录，不能据此正式发布。", "", "本文由 `tests/acceptance/implementation.json` 与正式需求目录生成。`python3 scripts/check_alignment.py --check` 核对引用、需求、API 和路由偏移；该命令通过只证明这些文件对齐，不证明功能正确、生产可用或性能合格。", "", "## 状态口径", "", "- **部分实现**：已有真实子流程，但没有完成整项需求的对象、权限、异常、页面或验收边界。", "- **待实现**：没有该业务流程。可复用的任务、数据库或原型不算该功能实现。", "- **实现待验收**：全部工程行为已交付，仍需独立真实验收。当前没有此状态条目。", "- **验收通过**：仅由同一提交的真实功能证据、覆盖率、远程部署和发行包门禁确定，不由本清单生成。", "", "原型提供目标交互，协议测试验证适配契约；两者均不能代替真实模型效果、设备封禁、办公渠道送达、对象存储保护或沙箱运行验收。所有业务分类默认保留 180 天，用户自定义策略、全域清理与保全仍须完整实现；短期 WAL/缓存和证书期限不属于业务留存。", "", "## 领域总览", "", "| 领域 | 需求数 | 部分实现 | 待实现 | 完整实现待验收 |", "| --- | ---: | ---: | ---: | ---: |"]
    for domain, name in DOMAINS.items():
        selected = [item for id, item in by_id.items() if id.startswith("SB-" + domain + "-")]
        c = collections.Counter(item["state"] for item in selected)
        lines.append(f"| {name} | {len(selected)} | {c['partial']} | {c['missing']} | {c['implemented']} |")
    lines += ["", "## 实现依据", "", "下列链接是当前代码和可执行测试入口，不是完整验收证书。逐项表通过能力名称引用这些来源。", ""]
    for cap in inventory["capabilities"]:
        lines += [f"### {cap['name']}", "", cap["boundary"], "", "代码：" + "、".join(f"[{path}](../{path})" for path in cap["code"]) + "。", "", "测试入口：" + "、".join(f"[{path}](../{path})" for path in cap["tests"]) + "。", ""]
        if cap["pages"]:
            lines += ["工程页面：" + "、".join(f"`{page}`" for page in cap["pages"]) + "。", ""]
    lines += ["## 当前 HTTP 与工程页面", "", f"[平台 OpenAPI](../api/openapi/platform.json) 包含 {len(api['platform'])} 个业务操作；[采集器 OpenAPI](../api/openapi/collector.json) 包含 {len(api['collector'])} 个业务操作。注册方法与路径逐项比对，认证、CSRF、写入只读凭据、修订冲突和未知结果见接口契约。`/healthz`、`/readyz`、`/metrics` 属于独立运维入口。", "", "[工程验收路由](../tests/acceptance/routes.json) 包含平台 " + str(len(routes["platform"])) + " 个路由/页签状态和采集器 " + str(len(routes["collector"])) + " 个，其中包括登录与 404；列入清单不表示七档 PC 宽度与全部交互已经通过真实浏览器验收。", "", "## 逐项需求", "", "以下均为未完整验收。实现内容和缺口分别记录，不以一个已运行子流程代替整项复合需求。", "", "| 需求 ID／名称 | 工程状态 | 实际子流程／能力引用 | 仍需交付和验收 |", "| --- | --- | --- | --- |"]
    cap_names = {item["id"]: item["name"] for item in inventory["capabilities"]}
    for requirement in registry["requirements"]:
        item = by_id[requirement["id"]]
        implemented = "；".join(item["implemented"]) or "尚无对应工程流程"
        if item["capabilities"]:
            implemented += "。依据：" + "、".join(cap_names[id] for id in item["capabilities"])
        lines.append("| " + " | ".join(cell(text) for text in (requirement["id"] + " " + requirement["name"], STATES[item["state"]], implemented, "；".join(item["remaining"]) or "须完成真实功能验收")) + " |")
    lines += ["", "## 工程依赖", "", "以下为根 `go.mod` 当前直接模块，未被实际代码调用的候选组件只保留在目标选型文档。版本核定与目标部署见[依赖版本与部署清单](依赖版本与部署清单.md)。", "", "| 当前直接模块 | 锁定版本 |", "| --- | --- |"]
    for name, version in direct_modules(root):
        lines.append(f"| `{name}` | `{version}` |")
    lines += ["", "## 发布阻塞项", ""] + ["- " + text for text in inventory["release_blockers"]]
    lines += ["", "真实验收必须使用同一源码快照/提交，保留原始测试日志和摘要。本轮远程运行属于独立 Docker 开发模式；后端测试通过不等同生产 TLS/R3/HA、全功能、全屏幕交互或发行包验收。历史覆盖率不能与当前代码混算，原生离线重放时延不能作为在线大流量承诺。", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="只检查已生成文档是否与当前实现清单一致")
    args = parser.parse_args()
    try:
        registry = load(ROOT, "tests/acceptance/requirements.json")
        inventory = load(ROOT, "tests/acceptance/implementation.json")
        routes = load(ROOT, "tests/acceptance/routes.json")
        validate_inventory(ROOT, registry, inventory)
        api = {role: validate_api(ROOT, role, load(ROOT, f"api/openapi/{role}.json")) for role in ("platform", "collector")}
        validate_routes(ROOT, routes, inventory)
        document = render(ROOT, registry, inventory, api, routes)
        if args.check:
            if (ROOT / OUTPUT).read_text() != document:
                raise ValueError("功能状态文档与实现清单不一致；需重新生成并核对")
        else:
            (ROOT / OUTPUT).write_text(document)
        print(f"需求、实现、API、路由及文档对齐：107 项；平台 {len(api['platform'])} 个 HTTP 操作，采集器 {len(api['collector'])} 个。此检查不代替功能验收。")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"对齐检查失败：{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
