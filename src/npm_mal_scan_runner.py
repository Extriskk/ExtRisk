"""
Run npm-mal-scan (npm malware / supply-chain scanner) from this repo.

Resolution order for the scanner root (directory containing bin/scan.js):
  1. Environment variable NPM_MAL_SCAN_ROOT
  2. tools/npm-mal-scan (clone, submodule, or directory junction)
  3. Sibling directory ../npm-project (common when both repos live under GitHub/)

The scanner is TypeScript; run `npm install && npm run build` in that directory once.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from subprocess import CompletedProcess
from typing import Optional


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def resolve_npm_mal_scan_root() -> Path | None:
    env = os.environ.get("NPM_MAL_SCAN_ROOT", "").strip()
    if env:
        p = Path(env).expanduser().resolve()
        if (p / "bin" / "scan.js").is_file():
            return p

    root = repo_root()
    for candidate in (
        root / "tools" / "npm-mal-scan",
        root.parent / "npm-project",
    ):
        if (candidate / "bin" / "scan.js").is_file():
            return candidate.resolve()
    return None


def npm_mal_scan_argv() -> tuple[list[str], Path] | None:
    """
    Return (argv, cwd) to run the scanner CLI, or None if not installed.
    Uses `node bin/scan.js` so a global npm link is not required.
    """
    scan_root = resolve_npm_mal_scan_root()
    if scan_root is None:
        return None
    node = shutil_which_node()
    if not node:
        return None
    script = scan_root / "bin" / "scan.js"
    return [node, str(script)], scan_root


def shutil_which_node() -> str | None:
    import shutil

    return shutil.which("node") or shutil.which("node.exe")


def run_npm_mal_scan(forward_argv: list[str], timeout: int | None = None) -> int:
    """
    Forward arguments to npm-mal-scan. Example:
        run_npm_mal_scan(["lodash", "4.17.21"])
    """
    found = npm_mal_scan_argv()
    if not found:
        root = repo_root()
        print(
            "[npm-mal-scan] Scanner not found. Install one of:\n"
            f"  - Clone or junction npm-mal-scan into: {root / 'tools' / 'npm-mal-scan'}\n"
            f"  - Or place sibling repo at: {root.parent / 'npm-project'}\n"
            "  - Or set NPM_MAL_SCAN_ROOT to the package root (contains bin/scan.js).\n"
            "Then: npm install && npm run build in that directory.",
            file=sys.stderr,
        )
        return 127
    argv, cwd = found
    # CLI lives in dist/; bin/scan.js requires built output
    if not (cwd / "dist" / "cli.js").is_file():
        print(
            f"[npm-mal-scan] Missing dist/cli.js under {cwd}. Run: npm install && npm run build",
            file=sys.stderr,
        )
        return 126
    full = argv + forward_argv
    try:
        proc = subprocess.run(full, cwd=cwd, timeout=timeout)
        return int(proc.returncode)
    except subprocess.TimeoutExpired:
        print("[npm-mal-scan] Command timed out.", file=sys.stderr)
        return 124
    except OSError as e:
        print(f"[npm-mal-scan] Failed to execute: {e}", file=sys.stderr)
        return 125


def run_npm_mal_scan_captured(
    forward_argv: list[str],
    timeout: int | None = None,
) -> CompletedProcess[str] | None:
    """
    Run npm-mal-scan and capture stdout/stderr (UTF-8).

    Returns None if Node or the scanner is missing or dist/cli.js is not built.
    May raise subprocess.TimeoutExpired (caller should catch).
    """
    found = npm_mal_scan_argv()
    if not found:
        return None
    argv, cwd = found
    if not (cwd / "dist" / "cli.js").is_file():
        return None
    full = argv + forward_argv
    return subprocess.run(
        full,
        cwd=cwd,
        timeout=timeout,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdin=subprocess.DEVNULL,
    )


def npm_mal_scan_unavailable_reason() -> Optional[str]:
    """Human-readable reason the scanner cannot run, or None if it appears ready."""
    if not shutil_which_node():
        return "Node.js is not on PATH (required to run npm-mal-scan)."
    root = resolve_npm_mal_scan_root()
    if root is None:
        r = repo_root()
        return (
            "npm-mal-scan is not installed. Clone or junction it to "
            f"{r / 'tools' / 'npm-mal-scan'} or set NPM_MAL_SCAN_ROOT."
        )
    if not (root / "dist" / "cli.js").is_file():
        return f"npm-mal-scan at {root} is not built (missing dist/cli.js). Run npm install && npm run build."
    return None


def main() -> None:
    sys.exit(run_npm_mal_scan(sys.argv[1:]))


if __name__ == "__main__":
    main()
