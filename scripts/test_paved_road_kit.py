#!/usr/bin/env python3
"""Adversarial unit test suite for the Portable Paved-Road Pipeline Kit (RFC-2026-11-22-48).

Pure Python 3 stdlib (zero external packages). Verifies:
  1. TestPRFormatter_DropsUnprovenAndStripsHTMLAndSecrets:
     - Unproven / speculative warnings are strictly dropped.
     - PR comments are hard-capped at <= 5 items with accurate overflow count.
     - <script>, <iframe>, <img>, javascript:, and triple-backtick breakouts are neutralized.
     - Canary OpenAI, Anthropic, AWS, GitHub, Bearer, and PEM private keys are scrubbed to zero raw bytes.
  2. TestWorkflowYAML_SHAPinnedAndNoPullRequestTarget:
     - All workflow YAML files in .github/workflows/ and workflow-templates/ declare explicit permissions
       (never write-all), never use pull_request_target, and pin every external action `uses:` to a
       40-hex commit SHA.
     - Negative adversarial cases prove the auditor catches unpinned actions, pull_request_target,
       and missing or overly broad permissions.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import format_fixforward_pr as fmt  # noqa: E402

_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_LINE_RE = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*['\"]?([^'\"#\s]+)['\"]?")
_PERMISSIONS_LINE_RE = re.compile(r"^\s*permissions\s*:\s*(.*)$")
_PRT_RE = re.compile(r"\bpull_request_target\b", re.IGNORECASE)

# Internal reusable workflows inside this org repo (e.g. starter templates calling bonjoski/.github).
_INTERNAL_REUSABLE_PREFIX = "bonjoski/.github/.github/workflows/"


def audit_workflow_yaml_text(text: str, filename: str = "<memory>") -> list[str]:
    """Static security auditor for GitHub Actions workflow YAML (stdlib-only)."""
    errors: list[str] = []
    has_permissions = False

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        # Strip inline YAML comments outside quotes for key/event inspection.
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        code_part = raw_line.split("#", 1)[0]

        if _PRT_RE.search(code_part):
            errors.append(f"{filename}:{lineno}: forbidden pull_request_target trigger detected")

        perm_match = _PERMISSIONS_LINE_RE.match(code_part)
        if perm_match:
            has_permissions = True
            val = perm_match.group(1).strip().lower()
            if val == "write-all":
                errors.append(f"{filename}:{lineno}: forbidden overly broad 'permissions: write-all'")

        uses_match = _USES_LINE_RE.match(code_part)
        if uses_match:
            target = uses_match.group(1)
            # Local composite actions (./...) and internal org reusable workflows are distinct from external actions.
            if target.startswith("./") or target.startswith(_INTERNAL_REUSABLE_PREFIX):
                continue
            if "@" not in target:
                errors.append(f"{filename}:{lineno}: external action {target!r} missing '@<40-hex-sha>' pin")
                continue
            _, ref = target.rsplit("@", 1)
            if not _SHA40_RE.match(ref):
                errors.append(
                    f"{filename}:{lineno}: external action {target!r} is NOT pinned to a 40-hex commit SHA (got {ref!r})"
                )

    if not has_permissions:
        errors.append(f"{filename}: missing explicit least-privilege 'permissions:' block")

    return errors


class TestPRFormatter_DropsUnprovenAndStripsHTMLAndSecrets(unittest.TestCase):
    def test_drops_unproven_and_caps_at_five_items(self) -> None:
        raw_findings = [
            # Unproven / speculative findings that MUST be dropped
            {"tool": "soulcaster", "proven": False, "summary": "Speculative warning 1", "why": "Noise"},
            {"tool": "aegisbox", "summary": "Missing proven flag must drop", "why": "Noise"},
            {"tool": "argus", "proven": "true", "summary": "String true must drop (fail closed)", "why": "Noise"},
            {"tool": "argus", "proven": None, "summary": "Null proven must drop", "why": "Noise"},
        ]
        # Add 7 proven findings to verify hard cap <= 5 + overflow count == 2
        for i in range(1, 8):
            raw_findings.append(
                {
                    "tool": "aegisbox",
                    "probe_id": f"PROBE-0{i}",
                    "proven": True,
                    "summary": f"Proven issue #{i}",
                    "why_one_liner": f"Deterministic failure reason #{i}",
                    "fix_patch_hint": f"// patch #{i}\nreturn ErrScopeDenied",
                }
            )

        # Even if caller asks for max_items=99, formatter MUST enforce <= 5.
        rendered = fmt.format_pr_comment(
            raw_findings,
            max_items=99,
            run_url="https://github.com/bonjoski/example/actions/runs/12345",
        )

        self.assertNotIn("Speculative warning 1", rendered)
        self.assertNotIn("Missing proven flag must drop", rendered)
        self.assertNotIn("String true must drop", rendered)
        self.assertNotIn("Null proven must drop", rendered)

        for i in range(1, 6):
            self.assertIn(f"### {i}. Proven issue #{i}", rendered)
        self.assertNotIn("Proven issue #6", rendered)
        self.assertNotIn("Proven issue #7", rendered)
        self.assertIn("+2 additional proven finding(s) omitted", rendered)
        self.assertIn("https://github.com/bonjoski/example/actions/runs/12345", rendered)

    def test_neutralizes_html_xss_and_triple_backtick_breakout(self) -> None:
        hostile = [
            {
                "tool": "aegisbox",
                "proven": True,
                "summary": 'XSS <script>alert(1)</script> and <img src=x onerror="alert(2)">',
                "why_one_liner": 'Click [here](javascript:alert(3)) or <iframe src="https://evil.test"></iframe>',
                "fix_patch_hint": 'ok\n```\n<script>fetch("https://evil.test")</script>\njavascript:alert(9)\n```\nmore',
            }
        ]

        rendered = fmt.format_pr_comment(hostile, run_url="javascript:alert(1)")

        lower = rendered.lower()
        self.assertNotIn("<script", lower)
        self.assertNotIn("</script", lower)
        self.assertNotIn("<iframe", lower)
        self.assertNotIn("<img", lower)
        self.assertNotIn("onerror=", lower)
        self.assertNotIn("javascript:", lower)
        # Only the single outer ```text ... ``` block should exist (exactly 2 fence lines).
        fence_lines = [ln for ln in rendered.splitlines() if ln.strip().startswith("```")]
        self.assertEqual(len(fence_lines), 2, f"Expected exactly 2 fence delimiters, got: {fence_lines!r}")

    def test_scrubs_all_canary_secrets_to_zero_raw_bytes(self) -> None:
        canaries = {
            "openai_proj": "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456",
            "openai_legacy": "sk-1234567890abcdefghijklmnop",
            "anthropic": "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz9999",
            "aws": "AKIAIOSFODNN7EXAMPLE",
            "gh_classic": "ghp_1234567890abcdefghijklmnopqrstuvwx",
            "gh_pat": "github_pat_11AAAAAA0123456789_abcdefghijklmnop",
            "bearer": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig",
            "pem_body": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC",
        }
        pem_secret = (
            "-----BEGIN PRIVATE KEY-----\n"
            f"{canaries['pem_body']}\n"
            "-----END PRIVATE KEY-----"
        )

        hostile = [
            {
                "tool": "soulcaster",
                "proven": True,
                "summary": f"Leaked {canaries['openai_proj']} and {canaries['aws']} and {canaries['gh_classic']}",
                "why_one_liner": f"Anthropic {canaries['anthropic']} / PAT {canaries['gh_pat']} / Bearer {canaries['bearer']}",
                "fix_patch_hint": f"Remove {canaries['openai_legacy']} and:\n{pem_secret}",
            }
        ]

        rendered = fmt.format_pr_comment(hostile)

        for label, secret in canaries.items():
            self.assertNotIn(secret, rendered, f"Canary secret {label} leaked into rendered PR comment!")
        self.assertNotIn("BEGIN PRIVATE KEY", rendered)
        self.assertIn("[REDACTED_OPENAI_KEY]", rendered)
        self.assertIn("[REDACTED_ANTHROPIC_KEY]", rendered)
        self.assertIn("[REDACTED_AWS_KEY]", rendered)
        self.assertIn("[REDACTED_GITHUB_TOKEN]", rendered)
        self.assertIn("[REDACTED_BEARER_TOKEN]", rendered)
        self.assertIn("[REDACTED_PEM_KEY]", rendered)

    def test_cli_end_to_end_multi_tool_aggregation_and_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            argus_file = tmp_dir / "argus.json"
            soul_file = tmp_dir / "soulcaster.json"
            aegis_file = tmp_dir / "aegisbox.json"
            out_file = tmp_dir / "comment.md"

            argus_file.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "id": "ARGUS-SLOP-01",
                                "proven": True,
                                "package": "reqeusts-helper",
                                "summary": "Blocked slopsquatted package reqeusts-helper",
                                "why": "Package does not exist on PyPI and matches typosquat heuristic.",
                                "fix": "Remove reqeusts-helper and depend on requests.",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            soul_file.write_text(
                json.dumps(
                    {
                        "findings": [
                            {"proven": False, "summary": "Unproven AST hint should be dropped"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            aegis_file.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "probe_id": "AEG-MCP-01",
                                "proven": True,
                                "summary": "Tool refund_order accepted amount above cap",
                                "why_one_liner": "Deterministic policy check missing outside LLM loop.",
                                "fix_patch_hint": "if err := policy.Authorize(ctx, req); err != nil { return err }",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS_DIR / "format_fixforward_pr.py"),
                    "--argus",
                    str(argus_file),
                    "--soulcaster",
                    str(soul_file),
                    "--aegisbox",
                    str(aegis_file),
                    "--output",
                    str(out_file),
                    "--fail-on-proven",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, f"Expected exit code 1 on proven findings; stderr={proc.stderr}")
            body = out_file.read_text(encoding="utf-8")
            self.assertIn("Blocked slopsquatted package", body)
            self.assertIn("Tool refund_order accepted amount above cap", body)
            self.assertNotIn("Unproven AST hint should be dropped", body)


class TestWorkflowYAML_SHAPinnedAndNoPullRequestTarget(unittest.TestCase):
    def test_all_repo_workflows_and_templates_are_hardened(self) -> None:
        workflow_dirs = [
            REPO_ROOT / ".github" / "workflows",
            REPO_ROOT / "workflow-templates",
        ]
        discovered: list[Path] = []
        for directory in workflow_dirs:
            self.assertTrue(directory.is_dir(), f"Expected workflow directory to exist: {directory}")
            for path in sorted(directory.glob("*.y*ml")):
                discovered.append(path)

        # Ensure our paved-road workflows exist in both directories.
        names = {p.relative_to(REPO_ROOT).as_posix() for p in discovered}
        for expected in (
            ".github/workflows/paved-road-pr.yml",
            ".github/workflows/paved-road-release.yml",
            "workflow-templates/paved-road-pr.yml",
            "workflow-templates/paved-road-release.yml",
        ):
            self.assertIn(expected, names, f"Missing required paved-road workflow: {expected}")

        # Verify companion .properties.json files are valid JSON with required metadata.
        for prop_rel in (
            "workflow-templates/paved-road-pr.properties.json",
            "workflow-templates/paved-road-release.properties.json",
        ):
            prop_path = REPO_ROOT / prop_rel
            self.assertTrue(prop_path.is_file(), f"Missing properties file: {prop_rel}")
            meta = json.loads(prop_path.read_text(encoding="utf-8"))
            self.assertTrue(meta.get("name"))
            self.assertTrue(meta.get("description"))
            self.assertIsInstance(meta.get("categories"), list)

        all_errors: list[str] = []
        for wf_path in discovered:
            rel = wf_path.relative_to(REPO_ROOT).as_posix()
            all_errors.extend(audit_workflow_yaml_text(wf_path.read_text(encoding="utf-8"), filename=rel))

        self.assertEqual(all_errors, [], "Workflow security audit failed:\n" + "\n".join(all_errors))

    def test_auditor_rejects_unpinned_actions_pull_request_target_and_missing_permissions(self) -> None:
        bad_yaml = """
name: Insecure Workflow
on:
  pull_request_target:
    branches: [main]
jobs:
  pwn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sigstore/cosign-installer@main
"""
        errs = audit_workflow_yaml_text(bad_yaml, filename="bad.yml")
        joined = "\n".join(errs)
        self.assertIn("pull_request_target", joined)
        self.assertIn("actions/checkout@v4", joined)
        self.assertIn("sigstore/cosign-installer@main", joined)
        self.assertIn("missing explicit least-privilege 'permissions:' block", joined)

        broad_perm_yaml = """
name: Broad Permissions
permissions: write-all
on: [push]
jobs:
  noop:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
"""
        errs2 = audit_workflow_yaml_text(broad_perm_yaml, filename="broad.yml")
        self.assertTrue(any("write-all" in e for e in errs2), f"Expected write-all error, got {errs2}")


if __name__ == "__main__":
    unittest.main()
