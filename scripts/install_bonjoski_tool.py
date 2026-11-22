#!/usr/bin/env python3
"""Fail-closed, SHA-256-pinned binary installer for bonjoski CI dogfooding (RFC-2026-11-22-50).

Security invariants:
  1. Zero external dependencies (Python 3 stdlib only).
  2. Strict URL allowlist: only HTTPS downloads from https://github.com/bonjoski/<tool>/releases/download/...
  3. Exact 64-hex SHA-256 verification BEFORE any archive extraction.
  4. Anti-tar-slip & anti-symlink extraction: rejects '..', absolute paths, symlinks,
     hardlinks, and non-regular files; extracts ONLY the expected binary into dest_dir
     with mode 0755 using atomic rename.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import stat
import sys
import tarfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_BIN_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_ALLOWED_PREFIX = "https://github.com/bonjoski/"


class InstallSecurityError(ValueError):
    """Raised whenever a download, checksum, or archive violates fail-closed invariants."""


def detect_platform() -> str:
    sys_name = platform.system().lower()
    mach = platform.machine().lower()
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }
    arch = arch_map.get(mach)
    if sys_name not in ("linux", "darwin") or not arch:
        raise InstallSecurityError(f"Unsupported platform {sys_name}/{mach}")
    return f"{sys_name}_{arch}"


def validate_release_url(url: str, expected_tool: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        raise InstallSecurityError(f"Refusing untrusted download URL host: {url!r}")
    required_prefix = f"{_ALLOWED_PREFIX}{expected_tool}/releases/download/"
    if not url.startswith(required_prefix):
        raise InstallSecurityError(
            f"Refusing URL outside allowlisted release path {required_prefix!r}: {url!r}"
        )


def verify_sha256(data: bytes, expected_sha256: str) -> None:
    expected = expected_sha256.strip().lower()
    if not _SHA256_RE.match(expected):
        raise InstallSecurityError(f"Invalid expected SHA-256 digest: {expected_sha256!r}")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise InstallSecurityError(
            f"SHA-256 mismatch: expected {expected}, got {actual}"
        )


def _normalize_member_path(name: str) -> str:
    if "\x00" in name:
        raise InstallSecurityError(f"Null byte in archive member name: {name!r}")
    if name.startswith("/") or name.startswith("\\"):
        raise InstallSecurityError(f"Absolute path in archive member: {name!r}")
    # Strip benign leading './' emitted by BSD/GNU tar
    cleaned = name
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    parts = [p for p in cleaned.replace("\\", "/").split("/") if p]
    if any(p == ".." for p in parts):
        raise InstallSecurityError(f"Path traversal ('..') detected in archive member: {name!r}")
    return "/".join(parts)


def extract_verified_binary(
    archive_bytes: bytes,
    expected_sha256: str,
    binary_name: str,
    dest_dir: Path,
) -> Path:
    if not _SAFE_BIN_RE.match(binary_name):
        raise InstallSecurityError(f"Invalid binary name: {binary_name!r}")

    verify_sha256(archive_bytes, expected_sha256)

    dest_dir.mkdir(parents=True, exist_ok=True)
    if dest_dir.is_symlink():
        raise InstallSecurityError(f"Refusing symlink destination directory: {dest_dir}")

    extracted_payload: bytes | None = None
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            # Reject symlinks, hardlinks, devices, FIFOs anywhere in the archive
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise InstallSecurityError(
                    f"Forbidden special archive member ({member.type!r}): {member.name!r}"
                )
            norm = _normalize_member_path(member.name)
            if member.isdir() or norm in ("", "."):
                continue
            if not member.isreg():
                raise InstallSecurityError(f"Unsupported non-regular archive member: {member.name!r}")
            if norm == binary_name or Path(norm).name == binary_name and "/" not in norm:
                fh = tf.extractfile(member)
                if fh is None:
                    raise InstallSecurityError(f"Unable to read archive member: {member.name!r}")
                extracted_payload = fh.read()

    if not extracted_payload:
        raise InstallSecurityError(f"Expected binary {binary_name!r} not found in archive")

    final_path = dest_dir / binary_name
    tmp_path = dest_dir / f".{binary_name}.tmp.{os.getpid()}"
    if final_path.is_symlink():
        raise InstallSecurityError(f"Refusing to overwrite symlink target: {final_path}")

    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
        try:
            os.write(fd, extracted_payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(tmp_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        os.replace(tmp_path, final_path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise

    return final_path


def install_tool(
    manifest: dict[str, Any],
    tool_name: str,
    dest_dir: Path,
    target_platform: str | None = None,
) -> Path:
    tools = manifest.get("tools", {})
    if tool_name not in tools:
        raise InstallSecurityError(f"Unknown tool {tool_name!r} (not in pinned manifest)")
    entry = tools[tool_name]
    plat = target_platform or detect_platform()
    plat_entry = entry.get("platforms", {}).get(plat)
    if not plat_entry:
        raise InstallSecurityError(f"No pinned artifact for {tool_name} on platform {plat}")

    url = str(plat_entry["url"])
    expected_sha = str(plat_entry["sha256"])
    binary_name = str(entry["binary"])

    validate_release_url(url, tool_name)

    cached_bin = dest_dir / binary_name
    marker = dest_dir / f".{binary_name}.sha256"
    if cached_bin.is_file() and not cached_bin.is_symlink() and marker.is_file():
        if marker.read_text(encoding="utf-8").strip() == expected_sha:
            return cached_bin

    req = urllib.request.Request(url, headers={"User-Agent": "bonjoski-paved-road-installer/1.0"})
    with urllib.request.urlopen(req, timeout=45) as resp:
        archive_bytes = resp.read()

    out_path = extract_verified_binary(archive_bytes, expected_sha, binary_name, dest_dir)
    marker.write_text(expected_sha + "\n", encoding="utf-8")
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install SHA-256-verified bonjoski release binaries.")
    parser.add_argument("tools", nargs="+", help="Tool names from pinned-tools.json (e.g. argus soulcaster)")
    parser.add_argument(
        "--manifest",
        default=str(Path(__file__).resolve().parent / "pinned-tools.json"),
        help="Path to pinned-tools.json manifest",
    )
    parser.add_argument(
        "--dest",
        default=str(Path.home() / ".local" / "bin"),
        help="Destination directory for verified binaries",
    )
    parser.add_argument("--platform", default="", help="Override platform (linux_amd64|darwin_arm64)")
    parser.add_argument("--github-path", action="store_true", help="Append --dest to $GITHUB_PATH if set")
    args = parser.parse_args(argv)

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    dest_dir = Path(args.dest).resolve()

    for tool in args.tools:
        out = install_tool(manifest, tool, dest_dir, args.platform or None)
        print(f"✔ Installed verified {tool} -> {out}")

    if args.github_path and os.environ.get("GITHUB_PATH"):
        with open(os.environ["GITHUB_PATH"], "a", encoding="utf-8") as gh_path:
            gh_path.write(str(dest_dir) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InstallSecurityError as exc:
        print(f"::error::bonjoski pinned installer blocked: {exc}", file=sys.stderr)
        raise SystemExit(1)
