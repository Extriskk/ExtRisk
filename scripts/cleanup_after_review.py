"""
Cleanup extracted extension directories after Bablu review.

When a bablu_review_<extension_id>.json (or bablu_review_<safe_id>.json) exists
in the review directory for an extension in the batch manifest, delete that
extension's extraction_path to free disk. Reports and central store are kept.

Usage (from repo root):
  python scripts/cleanup_after_review.py --manifest batch_runs/batch_manifest_sample_small_2026-02-21.json
  python scripts/cleanup_after_review.py --manifest batch_runs/... --review-dir batch_runs/bablu_reviews --dry-run
"""

import argparse
import json
import re
import sys
from pathlib import Path


def repo_root():
    return Path(__file__).resolve().parent.parent


def safe_identifier(extension_id: str) -> str:
    return re.sub(r"[^\w\-.]", "_", extension_id)


def has_review_file(review_dir: Path, extension_id: str) -> bool:
    """True if bablu_review_<id>.json or bablu_review_<safe_id>.json exists."""
    a = review_dir / f"bablu_review_{extension_id}.json"
    b = review_dir / f"bablu_review_{safe_identifier(extension_id)}.json"
    return a.exists() or b.exists()


def main():
    parser = argparse.ArgumentParser(
        description="Delete extracted extension dirs for extensions that have a Bablu review file."
    )
    parser.add_argument("--manifest", type=Path, required=True, help="Path to batch manifest JSON")
    parser.add_argument(
        "--review-dir",
        type=Path,
        default=None,
        help="Directory containing bablu_review_<id>.json files (default: batch_runs/bablu_reviews)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Only print what would be deleted")
    args = parser.parse_args()

    repo = repo_root()
    manifest_path = args.manifest.resolve()
    if not manifest_path.is_file():
        print(f"[!] Manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)
    review_dir = args.review_dir or (repo / "batch_runs" / "bablu_reviews")
    review_dir = review_dir.resolve()
    if not review_dir.is_dir():
        print(f"[!] Review dir not found: {review_dir} (no reviews yet?)", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    extensions = manifest.get("extensions", [])

    deleted = 0
    for ext in extensions:
        ext_id = ext.get("id")
        extraction_path = ext.get("extraction_path")
        if not ext_id or not extraction_path:
            continue
        if not has_review_file(review_dir, ext_id):
            continue
        path = Path(extraction_path)
        if not path.exists():
            continue
        if not path.is_dir():
            continue
        if args.dry_run:
            print(f"[dry-run] Would delete: {path}")
        else:
            try:
                import shutil
                shutil.rmtree(path)
                print(f"  Deleted: {path}")
            except OSError as e:
                print(f"[!] Failed to delete {path}: {e}", file=sys.stderr)
        deleted += 1

    if args.dry_run:
        print(f"[dry-run] Would delete {deleted} extraction dir(s).")
    else:
        print(f"[+] Cleaned {deleted} extraction dir(s).")


if __name__ == "__main__":
    main()
