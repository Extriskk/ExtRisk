"""
Fetch recently updated VSCode extensions from the marketplace API and write a cohort JSON.

Uses the public gallery extensionquery API; fetches one page, sorts by lastUpdated
descending, and takes the first N extension IDs (publisher.extensionName).

Usage (from repo root):
  python scripts/fetch_recent_vscode_extensions.py
  python scripts/fetch_recent_vscode_extensions.py --count 20 --out data/cohorts/recent_20.json
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

API_URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery?api-version=3.0-preview.1"


def repo_root():
    return Path(__file__).resolve().parent.parent


def fetch_extensions_page(page_size: int = 100, page_number: int = 1) -> list:
    """Fetch one page of VS Code extensions (Target = Microsoft.VisualStudio.Code)."""
    body = {
        "filters": [
            {
                "criteria": [{"filterType": 8, "value": "Microsoft.VisualStudio.Code"}],
                "pageSize": page_size,
                "pageNumber": page_number,
            }
        ],
        "flags": 256,
    }
    resp = requests.post(
        API_URL,
        json=body,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    try:
        return data["results"][0]["extensions"]
    except (KeyError, IndexError):
        return []


def main():
    parser = argparse.ArgumentParser(description="Fetch recently updated VSCode extensions and write cohort JSON.")
    parser.add_argument("--count", type=int, default=10, help="Number of extensions to include (default 10)")
    parser.add_argument("--page-size", type=int, default=100, help="API page size (default 100)")
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output cohort path (default: data/cohorts/recent_<count>.json)",
    )
    args = parser.parse_args()

    if not requests:
        print("[!] Install requests: pip install requests", file=sys.stderr)
        sys.exit(1)

    repo = repo_root()
    out_path = args.out or repo / "data" / "cohorts" / f"recent_{args.count}.json"
    out_path = out_path.resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[i] Fetching up to {args.page_size} extensions from marketplace...")
    extensions = fetch_extensions_page(page_size=args.page_size, page_number=1)
    if not extensions:
        print("[!] No extensions returned from API", file=sys.stderr)
        sys.exit(1)

    # Sort by lastUpdated descending (most recent first)
    def sort_key(ext):
        return ext.get("lastUpdated") or ext.get("releaseDate") or ""

    extensions.sort(key=sort_key, reverse=True)
    take = min(args.count, len(extensions))
    selected = extensions[:take]

    extension_ids = []
    for ext in selected:
        pub = ext.get("publisher", {}) or {}
        pub_name = pub.get("publisherName") or ""
        ext_name = ext.get("extensionName") or ""
        if pub_name and ext_name:
            extension_ids.append(f"{pub_name}.{ext_name}")
        else:
            print(f"[!] Skip extension with missing publisher/name: {ext.get('extensionId')}", file=sys.stderr)

    cohort = {
        "name": out_path.stem,
        "description": f"Recently updated VSCode extensions from marketplace (top {take} by lastUpdated)",
        "extension_ids": extension_ids,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(cohort, f, indent=2)

    print(f"[+] Wrote {len(extension_ids)} extension IDs to {out_path}")
    for eid in extension_ids:
        print(f"    {eid}")


if __name__ == "__main__":
    main()
