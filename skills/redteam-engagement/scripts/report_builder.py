#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""report_builder — 把 findings JSON 转成客户可读的 Markdown 报告。

零依赖，只用 Python 3 标准库。

用法:
    python report_builder.py --findings findings.json --out report.md
    python report_builder.py --findings findings.json --strict
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION_FILE = ROOT / "VERSION"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}
MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def get_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


def cell(value) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def normalize_findings(data):
    warnings = []
    errors = []
    if not isinstance(data, dict):
        return None, ["根节点必须是对象"], warnings

    raw = data.get("findings")
    if not isinstance(raw, list):
        return None, ["缺少 findings 数组"], warnings

    findings = []
    seen_ids = set()
    for index, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            errors.append(f"第 {index} 条发现不是对象")
            continue

        fid = str(item.get("id") or f"F-{index:03d}")
        if fid in seen_ids:
            warnings.append(f"发现 ID 重复: {fid}")
        seen_ids.add(fid)

        title = str(item.get("title") or "").strip()
        if not title:
            errors.append(f"{fid}: 缺少 title")
            continue

        severity = str(item.get("severity") or "").strip().lower()
        if severity not in SEVERITY_ORDER:
            errors.append(f"{fid}: severity 必须是 {'/'.join(SEVERITY_ORDER)}")
            continue

        asset = str(item.get("asset") or "").strip()
        if not asset:
            warnings.append(f"{fid}: 缺少 asset")

        evidence = item.get("evidence") or []
        if isinstance(evidence, str):
            evidence = [evidence]
        evidence = [str(x) for x in evidence if str(x).strip()]
        if not evidence:
            warnings.append(f"{fid}: 缺少 evidence，报告中会标为待补充")

        mitre = item.get("mitre") or []
        if isinstance(mitre, str):
            mitre = [mitre]
        mitre = [str(x).strip().upper() for x in mitre if str(x).strip()]
        for tech in mitre:
            if not MITRE_RE.match(tech):
                warnings.append(f"{fid}: ATT&CK ID 格式可疑: {tech}")

        findings.append({
            "id": fid,
            "title": title,
            "severity": severity,
            "cvss": str(item.get("cvss") or "").strip(),
            "status": str(item.get("status") or "confirmed").strip(),
            "asset": asset,
            "mitre": mitre,
            "description": str(item.get("description") or "").strip(),
            "impact": str(item.get("impact") or "").strip(),
            "remediation": str(item.get("remediation") or "").strip(),
            "evidence": evidence,
        })

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["id"]))
    return findings, errors, warnings


def build_markdown(engagement, findings):
    meta = engagement or {}
    title = meta.get("name") or "红队评估报告"
    lines = [
        f"# {title}",
        "",
        f"> 客户：{meta.get('client') or '未填写'} ｜ 评估窗口：{meta.get('window') or '未填写'}",
        f"> 授权方：{meta.get('authorized_by') or '未填写'} ｜ 执行方：{meta.get('tester') or '未填写'}",
        f"> 报告生成：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## 执行摘要",
        "",
    ]

    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        counts[finding["severity"]] += 1
    parts = [f"{SEVERITY_LABEL[level]} {counts[level]}" for level in SEVERITY_ORDER if counts[level]]
    if findings:
        lines.append(
            f"本次评估共确认 {len(findings)} 个问题：" + "、".join(parts) + "。"
        )
        lines.append("")
        lines.append(
            f"最高风险为 **{SEVERITY_LABEL[findings[0]['severity']]}**："
            f"{findings[0]['title']}（{findings[0]['id']}）。"
        )
    else:
        lines.append("本次评估未确认有效问题。")
    lines.append("")

    if meta.get("methodology"):
        lines += ["## 评估方法", "", str(meta["methodology"]), ""]

    if meta.get("scope"):
        scope = meta["scope"]
        scope_items = scope if isinstance(scope, list) else [scope]
        lines += ["## 评估范围", ""]
        lines += [f"- {item}" for item in scope_items]
        lines.append("")

    lines += [
        "## 发现总览",
        "",
        "| ID | 级别 | 标题 | 资产 | ATT&CK |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        lines.append(
            f"| {cell(finding['id'])} | {SEVERITY_LABEL[finding['severity']]} "
            f"| {cell(finding['title'])} | {cell(finding['asset'])} "
            f"| {cell('、'.join(finding['mitre']))} |"
        )
    if not findings:
        lines.append("| - | - | 无 | - | - |")
    lines.append("")

    lines += ["## 详细发现", ""]
    if not findings:
        lines += ["无。", ""]
    for finding in findings:
        lines.append(f"### {finding['id']} {finding['title']}")
        lines.append("")
        lines.append(f"- 级别：{SEVERITY_LABEL[finding['severity']]}（{finding['severity']}）")
        lines.append(f"- CVSS：{finding['cvss'] or '未评分'}")
        status_label = "已确认" if finding["status"] == "confirmed" else finding["status"]
        lines.append(f"- 状态：{status_label}")
        lines.append(f"- 资产：{finding['asset'] or '未填写'}")
        lines.append(f"- ATT&CK：{'、'.join(finding['mitre']) or '未映射'}")
        lines.append("")
        lines.append("**描述**")
        lines.append("")
        lines.append(finding["description"] or "待补充。")
        lines.append("")
        lines.append("**影响**")
        lines.append("")
        lines.append(finding["impact"] or "待补充。")
        lines.append("")
        lines.append("**证据**")
        lines.append("")
        if finding["evidence"]:
            for block in finding["evidence"]:
                for raw_line in block.splitlines() or [""]:
                    lines.append(f"    {raw_line}")
                lines.append("")
        else:
            lines += ["待补充。", ""]
        lines.append("**修复建议**")
        lines.append("")
        lines.append(finding["remediation"] or "待补充。")
        lines.append("")

    tech_map = {}
    for finding in findings:
        for tech in finding["mitre"]:
            tech_map.setdefault(tech, []).append(finding["id"])
    if tech_map:
        lines += [
            "## ATT&CK 映射",
            "",
            "| 技术 ID | 关联发现 |",
            "| --- | --- |",
        ]
        for tech in sorted(tech_map):
            lines.append(f"| {tech} | {', '.join(tech_map[tech])} |")
        lines.append("")

    lines += [
        "## 说明",
        "",
        "- 本报告仅覆盖授权范围内的测试结果，未对范围外资产做任何验证。",
        "- 报告中不包含明文凭据与真实业务数据；证据已做必要脱敏。",
        "- 修复建议按优先级排列，具体实施方案需结合客户环境评估。",
    ]
    return "\n".join(lines).rstrip() + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="把 findings JSON 转成 Markdown 报告")
    parser.add_argument("--findings", required=True, help="findings JSON 文件")
    parser.add_argument("--out", default="report.md", help="输出 Markdown 路径，默认 report.md")
    parser.add_argument("--strict", action="store_true", help="存在警告时返回非零退出码")
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    args = parser.parse_args(argv)

    path = Path(args.findings)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        print(f"[!] 无法读取 {path}: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"[!] JSON 解析失败: 第 {exc.lineno} 行 {exc.msg}", file=sys.stderr)
        return 2

    findings, errors, warnings = normalize_findings(data)
    for warning in warnings:
        print(f"[WARN] {warning}", file=sys.stderr)
    if errors:
        for error in errors:
            print(f"[ERROR] {error}", file=sys.stderr)
        return 2

    markdown = build_markdown(data.get("engagement") or {}, findings)
    out = Path(args.out)
    out.write_text(markdown, encoding="utf-8")
    print(f"[OK] {len(findings)} findings written to {out}")
    if args.strict and warnings:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    raise SystemExit(main())
