import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable

SCOPE = {
    "engagement": "测试项目",
    "authorized_by": "测试授权方",
    "window": {
        "start": "2026-11-01T09:00:00+08:00",
        "end": "2026-11-10T18:00:00+08:00",
    },
    "targets": ["app.example.com", "*.api.example.com", "10.10.0.0/24"],
    "excludes": ["pay.example.com", "10.10.0.5"],
    "allowed_techniques": ["recon", "web"],
    "prohibited": ["phishing"],
}


def run(args, cwd=None):
    return subprocess.run(
        [PY, *args], cwd=cwd or ROOT, capture_output=True,
        text=True, encoding="utf-8", errors="replace",
    )


class ScopeCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scope = Path(self.tmp.name) / "scope.json"
        self.scope.write_text(json.dumps(SCOPE), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, target, technique=None, at="2026-11-05T10:00:00+08:00"):
        args = [
            "skills/redteam-engagement/scripts/scope_check.py",
            "--scope", str(self.scope), "--target", target,
        ]
        if technique:
            args += ["--technique", technique]
        if at:
            args += ["--at", at]
        return run(args)

    def test_allowed(self):
        result = self.check("app.example.com", "web")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("ALLOW", result.stdout)

    def test_excluded(self):
        result = self.check("pay.example.com", "web")
        self.assertEqual(result.returncode, 3)
        self.assertIn("排除项", result.stdout)

    def test_out_of_scope(self):
        result = self.check("evil.other.com", "web")
        self.assertEqual(result.returncode, 3)

    def test_prohibited_technique(self):
        result = self.check("app.example.com", "phishing")
        self.assertEqual(result.returncode, 3)

    def test_window_closed(self):
        result = self.check("app.example.com", "web", at="2026-11-20T10:00:00+08:00")
        self.assertEqual(result.returncode, 3)

    def test_cidr(self):
        result = self.check("10.10.0.8", "recon")
        self.assertEqual(result.returncode, 0)


class ReportBuilderTests(unittest.TestCase):
    def make_findings(self, evidence=True):
        return {
            "engagement": {"name": "测试报告", "client": "脱敏客户"},
            "findings": [{
                "id": "F-001",
                "title": "测试发现",
                "severity": "high",
                "asset": "https://app.example.com",
                "mitre": ["T1190"],
                "description": "描述",
                "evidence": ["请求示例"] if evidence else [],
                "impact": "影响",
                "remediation": "修复",
            }],
        }

    def run_builder(self, data, strict=False):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        findings = Path(tmp.name) / "findings.json"
        findings.write_text(json.dumps(data), encoding="utf-8")
        out = Path(tmp.name) / "report.md"
        args = [
            "skills/redteam-engagement/scripts/report_builder.py",
            "--findings", str(findings), "--out", str(out),
        ]
        if strict:
            args.append("--strict")
        result = run(args)
        return result, out

    def test_report_rendered(self):
        result, out = self.run_builder(self.make_findings())
        self.assertEqual(result.returncode, 0, result.stderr)
        text = out.read_text(encoding="utf-8")
        self.assertIn("发现总览", text)
        self.assertIn("ATT&CK 映射", text)
        self.assertIn("T1190", text)

    def test_strict_fails_on_missing_evidence(self):
        result, _ = self.run_builder(self.make_findings(evidence=False), strict=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("WARN", result.stderr)


if __name__ == "__main__":
    unittest.main()
