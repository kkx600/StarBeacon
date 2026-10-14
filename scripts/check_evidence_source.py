#!/usr/bin/env python3
"""只接受本仓库 main 同一提交的成功工程运行所产生的正式验收输入。"""
import re


def verify_source(run: dict, artifacts: dict, repository: str, commit: str, run_id: str) -> None:
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(r"[1-9][0-9]{0,19}", run_id):
        raise ValueError("提交或证据运行标识无效")
    if (not isinstance(run, dict) or str(run.get("id")) != run_id or run.get("head_sha") != commit
            or run.get("head_branch") != "main" or run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("event") not in ("push", "workflow_dispatch")
            or run.get("head_repository", {}).get("full_name") != repository
            or run.get("path") not in (".github/workflows/ci.yml", ".github/workflows/remote.yml")):
        raise ValueError("验收证据必须来自本仓库 main 同一提交的成功工程运行")
    if not isinstance(artifacts, dict) or not isinstance(artifacts.get("artifacts"), list):
        raise ValueError("验收制品目录不完整")
    matches = [a for a in artifacts["artifacts"] if isinstance(a, dict) and a.get("name") == "starbeacon-acceptance-input"]
    if len(matches) != 1 or matches[0].get("expired") is not False:
        raise ValueError("缺少唯一且未过期的完整验收输入制品；前端工程报告不能代替完整验收")
    origin = matches[0].get("workflow_run", {})
    if str(origin.get("id")) != run_id or origin.get("head_sha") != commit or origin.get("head_branch") != "main":
        raise ValueError("验收制品与来源运行不一致")
