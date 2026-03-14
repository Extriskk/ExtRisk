"""
List main/entry JS (and TS) files for a VSCode extension (for Bablu review).

Uses package.json main/browser, contributes entry points, and heuristics
(root/src/out/dist top-level .js/.ts/.mjs). Excludes node_modules and vendor dirs.

Usage (from repo root):
  python scripts/list_main_js.py --path data/vscode_extensions/publisher.name-1.0.0/extension
  python scripts/list_main_js.py --from-manifest batch_runs/batch_manifest_sample_small_2026-02-21.json --id dbaeumer.vscode-eslint
"""

import argparse
import json
import re
import sys
from pathlib import Path


def repo_root():
    return Path(__file__).resolve().parent.parent


def _normalize_path(p: str, base: Path) -> Path:
    p = p.strip().replace("\\", "/")
    if p.startswith("./"):
        p = p[2:]
    return (base / p).resolve()


def _collect_script_paths_from_value(val, base: Path, out: set) -> None:
    """Recursively collect paths that look like .js/.ts/.mjs from JSON value."""
    if isinstance(val, str):
        s = val.strip().replace("\\", "/")
        if s.endswith((".js", ".ts", ".mjs")) and not s.startswith("http"):
            if not s.startswith("/"):
                out.add(_normalize_path(s, base))
        return
    if isinstance(val, list):
        for item in val:
            _collect_script_paths_from_value(item, base, out)
        return
    if isinstance(val, dict):
        for v in val.values():
            _collect_script_paths_from_value(v, base, out)
        return


def list_main_js(extension_dir: Path) -> dict:
    """
    Return main JS/TS file paths for the extension.
    Keys: main_js_relative (list of paths relative to extension_dir), paths_absolute, entry_types (main/browser/contributes/toplevel).
    """
    extension_dir = Path(extension_dir).resolve()
    package_json = extension_dir / "package.json"
    if not package_json.exists():
        return {"error": "package.json not found", "main_js_relative": [], "paths_absolute": []}

    try:
        with open(package_json, encoding="utf-8") as f:
            pkg = json.load(f)
    except Exception as e:
        return {"error": str(e), "main_js_relative": [], "paths_absolute": []}

    collected: set[Path] = set()

    # package.json main / browser
    for key in ("main", "browser"):
        entry = pkg.get(key)
        if isinstance(entry, str) and entry.strip():
            p = _normalize_path(entry.strip(), extension_dir)
            if p.exists():
                collected.add(p)

    # contributes: any script path referenced
    contributes = pkg.get("contributes") or {}
    _collect_script_paths_from_value(contributes, extension_dir, collected)

    # Top-level .js/.ts/.mjs in extension root and one level under src/, out/, dist/
    for part in ["", "src", "out", "dist"]:
        dir_path = extension_dir / part if part else extension_dir
        if not dir_path.is_dir():
            continue
        for f in dir_path.iterdir():
            if f.is_file() and f.suffix.lower() in (".js", ".ts", ".mjs"):
                collected.add(f.resolve())

    # Filter to paths under extension_dir and existing
    under_base = [p for p in collected if p.exists() and extension_dir in p.parents or p == extension_dir]
    under_base = list(set(under_base))

    def rel(p: Path) -> str:
        try:
            return str(p.relative_to(extension_dir)).replace("\\", "/")
        except ValueError:
            return str(p)

    main_js_relative = sorted([rel(p) for p in under_base])
    paths_absolute = sorted([str(p) for p in under_base])

    return {
        "extension_dir": str(extension_dir),
        "main_js_relative": main_js_relative,
        "paths_absolute": paths_absolute,
        "entry_types": "main, browser, contributes, toplevel",
    }


def main():
    parser = argparse.ArgumentParser(description="List main JS/TS files for a VSCode extension (Bablu review).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--path", type=Path, help="Path to extracted extension directory (e.g. .../extension)")
    group.add_argument("--from-manifest", type=Path, help="Path to batch manifest JSON")
    parser.add_argument("--id", type=str, help="Extension ID (required if --from-manifest)")
    parser.add_argument("--json", action="store_true", help="Output full JSON; default is one path per line")
    args = parser.parse_args()

    if args.path:
        ext_dir = args.path.resolve()
        if not ext_dir.is_dir():
            print(f"[!] Not a directory: {ext_dir}", file=sys.stderr)
            sys.exit(1)
        result = list_main_js(ext_dir)
    else:
        if not args.id:
            print("[!] --id required when using --from-manifest", file=sys.stderr)
            sys.exit(1)
        manifest_path = args.from_manifest.resolve()
        if not manifest_path.is_file():
            print(f"[!] Manifest not found: {manifest_path}", file=sys.stderr)
            sys.exit(1)
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        ext_entry = next((e for e in manifest.get("extensions", []) if e.get("id") == args.id), None)
        if not ext_entry:
            print(f"[!] Extension id '{args.id}' not found in manifest", file=sys.stderr)
            sys.exit(1)
        ext_path = ext_entry.get("extraction_path")
        if not ext_path:
            print(f"[!] No extraction_path for {args.id} in manifest", file=sys.stderr)
            sys.exit(1)
        ext_dir = Path(ext_path)
        if not ext_dir.is_dir():
            print(f"[!] Extraction path not a directory: {ext_dir}", file=sys.stderr)
            sys.exit(1)
        result = list_main_js(ext_dir)
        result["extension_id"] = args.id

    if result.get("error"):
        print(result["error"], file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for p in result.get("main_js_relative", []):
            print(p)


if __name__ == "__main__":
    main()
