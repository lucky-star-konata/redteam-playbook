#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scope_check — 授权范围闸门：目标、时间窗口、手法逐项校验。

零依赖，只用 Python 3 标准库。

用法:
    python scope_check.py --scope scope.json --target api.example.com --technique web
    python scope_check.py --scope scope.json --target 10.0.0.8 --technique ad --json
    python scope_check.py --scope scope.json --at 2026-11-05T10:00:00+08:00 --target x.example.com
    python scope_check.py --scope scope.json --list
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[3]
VERSION_FILE = ROOT / "VERSION"


def get_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


def parse_time(value: str) -> datetime:
    """解析 ISO 8601；无时区时按本机时区处理"""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return dt


def host_of(value: str) -> str:
    """从 URL / host:port / 纯主机中提取主机名"""
    raw = value.strip()
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    elif raw.startswith("["):
        end = raw.find("]")
        if end != -1:
            raw = raw[1:end]
    elif raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            raw = host
    return raw.rstrip(".").lower()


def match_rule(target: str, rule: str) -> bool:
    """目标是否命中单条规则：支持域名、*.域名、IP、CIDR"""
    rule = rule.strip().rstrip(".").lower()
    try:
        network = ipaddress.ip_network(rule, strict=False)
    except ValueError:
        network = None
    if network is not None:
        try:
            return ipaddress.ip_address(target) in network
        except ValueError:
            return False
    if rule.startswith("*."):
        suffix = rule[2:]
        return target.endswith("." + suffix) and target != suffix
    return target == rule


def find_match(target: str, rules):
    for rule in rules:
        if match_rule(target, rule):
            return rule
    return None


def load_scope(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise ValueError(f"无法读取 scope 文件: {exc}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"scope JSON 解析失败: 第 {exc.lineno} 行 {exc.msg}")
    if not isinstance(data, dict):
        raise ValueError("scope 根节点必须是对象")
    if not data.get("targets"):
        raise ValueError("scope 缺少 targets")
    window = data.get("window") or {}
    if not window.get("start") or not window.get("end"):
        raise ValueError("scope 缺少 window.start / window.end")
    if not data.get("authorized_by"):
        raise ValueError("scope 缺少 authorized_by（授权方）")
    return data


def evaluate(scope, targets, technique, at):
    checks = []
    allowed_techniques = [str(t).lower() for t in scope.get("allowed_techniques") or []]
    prohibited = [str(t).lower() for t in scope.get("prohibited") or []]
    excludes = scope.get("excludes") or []
    target_rules = scope.get("targets") or []

    for raw in targets:
        target = host_of(raw)
        reasons = []

        excluded_by = find_match(target, excludes)
        if excluded_by:
            reasons.append(f"命中排除项 {excluded_by}")
        else:
            matched = find_match(target, target_rules)
            if matched:
                reasons.append(f"命中授权目标 {matched}")
            else:
                reasons.append("未命中任何授权目标")

        checks.append({
            "target": target,
            "excluded_by": excluded_by,
            "matched_rule": None if excluded_by else find_match(target, target_rules),
            "reasons": reasons,
            "allowed": not excluded_by and find_match(target, target_rules) is not None,
        })

    window = scope["window"]
    start, end = parse_time(window["start"]), parse_time(window["end"])
    now = at or datetime.now().astimezone()
    time_ok = start <= now <= end

    technique_result = None
    if technique:
        name = technique.strip().lower()
        if name in prohibited:
            technique_result = {"technique": name, "allowed": False, "reason": "属于禁止手法"}
        elif allowed_techniques and name not in allowed_techniques:
            technique_result = {"technique": name, "allowed": False, "reason": "不在允许手法列表"}
        else:
            technique_result = {"technique": name, "allowed": True, "reason": "允许"}

    allowed = (
        all(item["allowed"] for item in checks)
        and time_ok
        and (technique_result is None or technique_result["allowed"])
    )
    return {
        "engagement": scope.get("engagement") or scope.get("name"),
        "authorized_by": scope.get("authorized_by"),
        "targets": checks,
        "window": {
            "start": start.isoformat(),
            "end": end.isoformat(),
            "now": now.isoformat(),
            "allowed": time_ok,
        },
        "technique": technique_result,
        "allowed": allowed,
    }


def print_human(result):
    print(f"scope_check {get_version()} · {result['engagement'] or '未命名项目'}")
    print(f"授权方: {result['authorized_by']}")
    for item in result["targets"]:
        status = "ALLOW" if item["allowed"] else "DENY"
        print(f"[{status}] 目标 {item['target']}")
        for reason in item["reasons"]:
            print(f"        - {reason}")
    window = result["window"]
    print(
        f"[{'ALLOW' if window['allowed'] else 'DENY'}] 时间窗口 "
        f"{window['start']} ~ {window['end']}（当前 {window['now']}）"
    )
    if result["technique"]:
        tech = result["technique"]
        print(f"[{'ALLOW' if tech['allowed'] else 'DENY'}] 手法 {tech['technique']}: {tech['reason']}")
    print(f"结论: {'ALLOW' if result['allowed'] else 'DENY'}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="授权范围闸门：目标 / 时间窗口 / 手法校验")
    parser.add_argument("--scope", required=True, help="scope JSON 文件")
    parser.add_argument("--target", action="append", default=[], help="待校验目标，可多次指定")
    parser.add_argument("--technique", help="待执行手法，如 recon / web / ad / phishing")
    parser.add_argument("--at", help="指定检查时间（ISO 8601），默认当前时间")
    parser.add_argument("--list", action="store_true", help="打印授权范围摘要")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    args = parser.parse_args(argv)

    try:
        scope = load_scope(Path(args.scope))
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if args.list:
        print(json.dumps(scope, ensure_ascii=False, indent=2))
        return 0

    if not args.target:
        print("[!] 至少需要一个 --target", file=sys.stderr)
        return 2

    try:
        at = parse_time(args.at) if args.at else None
    except ValueError:
        print(f"[!] --at 时间格式无效: {args.at}", file=sys.stderr)
        return 2

    result = evaluate(scope, args.target, args.technique, at)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_human(result)

    return 0 if result["allowed"] else 3


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    raise SystemExit(main())
