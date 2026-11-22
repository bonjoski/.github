#!/usr/bin/env python3
"""Zero-dependency Fix-Forward PR comment formatter (RFC-2026-11-22-48).

Aggregates diff-only JSON reports from argus, soulcaster, and aegisbox and emits
a calm, UB-CLI-v2 Fix-Forward Markdown summary enforcing:
  1. Strict Proven-Only filter (drops unproven/speculative warnings).
  2. Hard cap of at most 5 items per PR comment (with overflow notice).
  3. HTML/XSS neutralization (<script>, <iframe>, <img>, javascript:) and
     Markdown triple-backtick fence breakout prevention.
  4. Secret-pattern redaction (OpenAI, Anthropic, AWS, GitHub, Bearer, PEM keys).

Safe Harbor Scope: Purely local, single-repository open-source CI formatter.
Zero external dependencies, zero cloud calls, zero telemetry.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

HARD_MAX_ITEMS = 5
MAX_COMMENT_BYTES = 8192

# Invisible / bidi / control runes that can spoof diffs or smuggle payloads.
_INVISIBLE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")

# Active HTML element blocks removed completely (including inner payload).
_DANGEROUS_BLOCK_RE = re.compile(
    r"<\s*(script|iframe|style|object|embed|svg)\b[^>]*>.*?<\s*/\s*\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
# Remaining raw HTML tags (including unclosed <script>, <img onerror=...>, <iframe ...>).
_RAW_HTML_TAG_RE = re.compile(r"<\s*/?\s*[a-zA-Z!/?][^>]*>?", re.DOTALL)

# Dangerous URI schemes (allowing sneaky whitespace/control chars inside scheme).
_DANGEROUS_URI_RE = re.compile(
    r"(?:j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t|v\s*b\s*s\s*c\s*r\s*i\s*p\s*t|d\s*a\s*t\s*a\s*:\s*text/html)\s*:",
    re.IGNORECASE,
)

# Markdown link neutralization when dangerous schemes appear.
_MD_LINK_RE = re.compile(r"(!?\[[^\]]*\])\(([^)]+)\)")

# Code-fence breakout sequences (3+ backticks or 3+ tildes).
_TRIPLE_BACKTICK_RE = re.compile(r"`{3,}")
_TRIPLE_TILDE_RE = re.compile(r"~{3,}")

# Secret redaction patterns (ordered most-specific first).
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # PEM private keys (complete block)
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        "[REDACTED_PEM_KEY]",
    ),
    # Truncated / unclosed PEM private key header + trailing base64 lines
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*$",
            re.IGNORECASE,
        ),
        "[REDACTED_PEM_KEY]",
    ),
    # Anthropic keys (check before generic sk-)
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{8,}\b"), "[REDACTED_ANTHROPIC_KEY]"),
    # OpenAI project / service-account / legacy keys
    (re.compile(r"\bsk-(?:proj|svcacct|live|test)-[A-Za-z0-9_-]{8,}\b"), "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "[REDACTED_OPENAI_KEY]"),
    # AWS Access Key IDs
    (re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    # GitHub personal / fine-grained / OAuth / App tokens
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    # Bearer tokens
    (re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{10,}"), r"\1[REDACTED_BEARER_TOKEN]"),
    # Explicit secret key assignments
    (
        re.compile(r"(?i)\b(aws_secret_access_key\s*[:=]\s*['\"]?)[A-Za-z0-9/+=]{20,}(['\"]?)"),
        r"\1[REDACTED_SECRET]\2",
    ),
)


def scrub_secrets(text: str) -> str:
    """Redact known API keys, tokens, Bearer headers, and PEM private keys."""
    if not text:
        return ""
    cleaned = text
    for pattern, replacement in _SECRET_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def _strip_dangerous_html_and_uris(text: str) -> str:
    cleaned = _INVISIBLE_RE.sub("", text)
    cleaned = _DANGEROUS_BLOCK_RE.sub("[removed-html]", cleaned)
    cleaned = _DANGEROUS_URI_RE.sub("[blocked-uri]:", cleaned)

    def _clean_md_link(match: re.Match[str]) -> str:
        label, target = match.group(1), match.group(2).strip()
        if not target.lower().startswith(("https://", "http://")):
            return f"{label}([blocked-link])"
        return f"{label}({target})"

    cleaned = _MD_LINK_RE.sub(_clean_md_link, cleaned)
    cleaned = _RAW_HTML_TAG_RE.sub("", cleaned)
    cleaned = html.escape(cleaned, quote=False)
    return cleaned


def sanitize_inline(text: str, max_len: int = 240) -> str:
    """Sanitize a single-line field (summary, why, location, tool name)."""
    if not text:
        return ""
    cleaned = scrub_secrets(str(text))
    cleaned = _strip_dangerous_html_and_uris(cleaned)
    cleaned = _TRIPLE_BACKTICK_RE.sub("` ` `", cleaned)
    cleaned = _TRIPLE_TILDE_RE.sub("~ ~ ~", cleaned)
    cleaned = re.sub(r"[\r\n\t]+", " ", cleaned).strip()
    cleaned = scrub_secrets(cleaned)
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3].rstrip() + "..."
    return cleaned


def sanitize_code_block(code: str, max_len: int = 800) -> str:
    """Sanitize a multi-line Fix code block while preventing fence breakouts and XSS."""
    if not code:
        return ""
    cleaned = scrub_secrets(str(code))
    cleaned = _INVISIBLE_RE.sub("", cleaned)
    cleaned = _DANGEROUS_BLOCK_RE.sub("[removed-html]", cleaned)
    cleaned = _DANGEROUS_URI_RE.sub("[blocked-uri]:", cleaned)
    # Remove/neutralize raw dangerous tags even inside code snippets so downstream renderers cannot misinterpret them.
    cleaned = re.sub(r"<\s*/?\s*(script|iframe|img|svg|object|embed)\b[^>]*>?", "[removed-tag]", cleaned, flags=re.IGNORECASE)
    # Neutralize any fence breakout sequences.
    cleaned = _TRIPLE_BACKTICK_RE.sub("` ` `", cleaned)
    cleaned = _TRIPLE_TILDE_RE.sub("~ ~ ~", cleaned)
    cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n").strip()
    cleaned = scrub_secrets(cleaned)
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 18].rstrip() + "\n# ... (truncated)"
    return cleaned


def _is_proven(raw: dict[str, Any], default_tool: str) -> bool:
    """Strict Proven-Only filter: returns True ONLY for explicitly verified findings."""
    if "proven" in raw:
        # Strict boolean True only (rejects False, None, "true", 1, etc.).
        return raw["proven"] is True

    # Explicit RFC §5.2 fallback for argus verified high-confidence slopsquat blocks.
    tool = str(raw.get("tool") or default_tool).strip().lower()
    if tool == "argus":
        return (
            raw.get("verified") is True
            and str(raw.get("action", "")).lower() == "block"
            and str(raw.get("confidence", "")).lower() == "high"
        )
    return False


def normalize_finding(raw: Any, default_tool: str = "paved-road") -> dict[str, str] | None:
    """Normalize a raw finding dict if and only if it passes the strict proven filter."""
    if not isinstance(raw, dict):
        return None
    if not _is_proven(raw, default_tool):
        return None

    tool = sanitize_inline(str(raw.get("tool") or default_tool), max_len=40) or "paved-road"
    finding_id = sanitize_inline(
        str(raw.get("probe_id") or raw.get("rule_id") or raw.get("id") or ""),
        max_len=64,
    )
    location = sanitize_inline(
        str(raw.get("location") or raw.get("file") or raw.get("package") or ""),
        max_len=120,
    )
    summary = sanitize_inline(
        str(raw.get("summary") or raw.get("message") or raw.get("observed_effect") or "Proven issue detected"),
        max_len=200,
    )
    why = sanitize_inline(
        str(raw.get("why_one_liner") or raw.get("why") or raw.get("rationale") or "Verified against PR diff with zero speculative noise."),
        max_len=220,
    )
    fix = sanitize_code_block(
        str(raw.get("fix_patch_hint") or raw.get("fix") or raw.get("remediation") or ""),
        max_len=800,
    )

    return {
        "tool": tool,
        "id": finding_id,
        "location": location,
        "summary": summary,
        "why": why,
        "fix": fix,
    }


def extract_findings_from_payload(payload: Any, default_tool: str = "paved-road") -> list[dict[str, str]]:
    """Extract and strictly filter proven findings from a parsed JSON report."""
    candidates: list[Any] = []
    if isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, dict):
        for key in ("findings", "violations", "blocked", "results", "issues"):
            val = payload.get(key)
            if isinstance(val, list):
                candidates.extend(val)
        if not candidates and ("proven" in payload or "summary" in payload):
            candidates.append(payload)

    proven: list[dict[str, str]] = []
    for item in candidates:
        norm = normalize_finding(item, default_tool=default_tool)
        if norm is not None:
            proven.append(norm)
    return proven


def _safe_https_url(url: str) -> str:
    candidate = scrub_secrets(url.strip())
    if not candidate.startswith("https://"):
        return ""
    if any(ch in candidate for ch in (" ", "\n", "\r", "\t", ")", "(", "<", ">", '"', "'")):
        return ""
    return candidate


def format_pr_comment(
    raw_findings: Iterable[dict[str, Any]],
    *,
    default_tool: str = "paved-road",
    max_items: int = HARD_MAX_ITEMS,
    run_url: str = "",
) -> str:
    """Render a zero-noise, sanitized, secret-scrubbed UB-CLI-v2 Fix-Forward PR comment."""
    effective_max = max(1, min(int(max_items), HARD_MAX_ITEMS))
    proven: list[dict[str, str]] = []
    for item in raw_findings:
        if isinstance(item, dict) and set(item.keys()) == {"tool", "id", "location", "summary", "why", "fix"}:
            # Already normalized; still re-sanitize fields defensively.
            proven.append(
                {
                    "tool": sanitize_inline(item["tool"], max_len=40),
                    "id": sanitize_inline(item["id"], max_len=64),
                    "location": sanitize_inline(item["location"], max_len=120),
                    "summary": sanitize_inline(item["summary"], max_len=200),
                    "why": sanitize_inline(item["why"], max_len=220),
                    "fix": sanitize_code_block(item["fix"], max_len=800),
                }
            )
        else:
            norm = normalize_finding(item, default_tool=default_tool)
            if norm is not None:
                proven.append(norm)

    lines: list[str] = ["## Paved-Road Diff Gate (Proven Checks Only)", ""]
    if not proven:
        lines.append("All diff-only proven checks passed (0 proven findings).")
        return scrub_secrets("\n".join(lines) + "\n")

    shown = proven[:effective_max]
    overflow = len(proven) - len(shown)

    lines.append(
        f"Found **{len(proven)}** proven issue(s) in this PR diff (showing {len(shown)} of {len(proven)}; unverified alerts omitted)."
    )
    lines.append("")

    for idx, finding in enumerate(shown, start=1):
        meta_parts = [f"`{finding['tool']}`"]
        if finding["id"]:
            meta_parts.append(f"`{finding['id']}`")
        if finding["location"]:
            meta_parts.append(f"`{finding['location']}`")
        meta = " · ".join(meta_parts)

        lines.append(f"### {idx}. {finding['summary']}")
        lines.append(f"- **Source:** {meta}")
        lines.append(f"- **Why:** {finding['why']}")
        if finding["fix"]:
            lines.append("- **Fix:**")
            lines.append("```text")
            lines.append(finding["fix"])
            lines.append("```")
        lines.append("")

    if overflow > 0:
        safe_url = _safe_https_url(run_url)
        if safe_url:
            lines.append(
                f"_+{overflow} additional proven finding(s) omitted to keep PR reviews noise-free. "
                f"[View full Actions summary]({safe_url})._"
            )
        else:
            lines.append(
                f"_+{overflow} additional proven finding(s) omitted to keep PR reviews noise-free. "
                "See the workflow run summary for full details._"
            )

    rendered = scrub_secrets("\n".join(lines).rstrip() + "\n")
    encoded = rendered.encode("utf-8")
    if len(encoded) > MAX_COMMENT_BYTES:
        rendered = encoded[: MAX_COMMENT_BYTES - 48].decode("utf-8", errors="ignore").rstrip()
        rendered += "\n\n_(Truncated to 8 KiB PR comment safety budget.)_\n"
        rendered = scrub_secrets(rendered)
    return rendered


def _load_json_file(path_str: str) -> Any:
    path = Path(path_str)
    if not path.is_file():
        return None
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return None
    return json.loads(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Format diff-only proven findings from argus, soulcaster, and aegisbox into a Fix-Forward PR comment."
    )
    parser.add_argument("--argus", action="append", default=[], help="Path to argus vet --diff --json output")
    parser.add_argument("--soulcaster", action="append", default=[], help="Path to soulcaster verify-patch --json output")
    parser.add_argument("--aegisbox", action="append", default=[], help="Path to aegisbox test --ai-safety --json output")
    parser.add_argument("--input", action="append", default=[], help="Generic JSON finding file")
    parser.add_argument("--max-items", type=int, default=HARD_MAX_ITEMS, help="Max findings in comment (capped at 5)")
    parser.add_argument("--run-url", default="", help="Optional https:// GitHub Actions run URL for overflow link")
    parser.add_argument("--output", default="", help="Write rendered markdown to file instead of stdout")
    parser.add_argument("--fail-on-proven", action="store_true", help="Exit 1 if any proven finding is present")
    args = parser.parse_args(argv)

    proven_findings: list[dict[str, str]] = []
    sources: list[tuple[str, list[str]]] = [
        ("argus", args.argus),
        ("soulcaster", args.soulcaster),
        ("aegisbox", args.aegisbox),
        ("paved-road", args.input),
    ]
    for tool_name, paths in sources:
        for path_str in paths:
            payload = _load_json_file(path_str)
            if payload is not None:
                proven_findings.extend(extract_findings_from_payload(payload, default_tool=tool_name))

    comment = format_pr_comment(
        proven_findings,
        max_items=args.max_items,
        run_url=args.run_url,
    )

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(comment, encoding="utf-8")
    else:
        sys.stdout.write(comment)

    if args.fail_on_proven and proven_findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
