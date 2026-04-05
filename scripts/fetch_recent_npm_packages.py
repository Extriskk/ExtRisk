"""
List npm packages whose registry metadata was updated within a recent time window.

The npm website line "Published 2 years ago" is derived from the same registry
data as the **last-modified** time on the package document. For a given version,
`GET https://registry.npmjs.org/<pkg>` (full packument) includes per-version
timestamps under `time[<version>]`; the abbreviated install-v1 view exposes
`modified` (document last change), which tracks the latest publish for typical
flows.

This script uses the public **replicate.npmjs.com** CouchDB-style `_changes`
feed (newest-first) to discover candidate package names, then filters by
`modified` from:

  GET https://registry.npmjs.org/<encoded-name>
  Accept: application/vnd.npm.install-v1+json

Usage (from repo root):

  python scripts/fetch_recent_npm_packages.py --within-hours 24
  python scripts/fetch_recent_npm_packages.py --within-hours 24 --out data/cohorts/npm_last_day.json
  python scripts/fetch_recent_npm_packages.py --within-hours 48 --changes-limit 3000 --max-batches 5

Notes:
  - High publish volume: widen --changes-limit / --max-batches if results thin out.
  - The changes feed can shift between pages; names are deduped.
  - 404 on a name is skipped (unpublished / renamed edge cases).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

REPLICATE_CHANGES = "https://replicate.npmjs.com/_changes"
REGISTRY_PKG = "https://registry.npmjs.org"
INSTALL_V1_ACCEPT = "application/vnd.npm.install-v1+json"

DEFAULT_UA = (
    "fetch_recent_npm_packages/1.0 "
    "(+https://github.com/; npm registry metadata; security research)"
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_npm_time(s: str) -> Optional[datetime]:
    if not s or not isinstance(s, str):
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _registry_package_url(name: str) -> str:
    return f"{REGISTRY_PKG}/{quote(name, safe='')}"


def fetch_changes_batch(
    *,
    descending: bool,
    limit: int,
    since: Optional[int],
    user_agent: str,
    timeout: float,
) -> dict[str, Any]:
    params: list[str] = [f"limit={int(limit)}"]
    if descending:
        params.append("descending=true")
    if since is not None:
        params.append(f"since={int(since)}")
    url = REPLICATE_CHANGES + "?" + "&".join(params)
    req = Request(url, headers={"User-Agent": user_agent, "Accept": "application/json"})
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_modified_abbrev(
    name: str, *, user_agent: str, timeout: float
) -> tuple[str, Optional[str], Optional[str], Optional[str]]:
    """
    Returns (name, modified_iso_or_None, latest_version_or_None, error_or_None).
    """
    url = _registry_package_url(name)
    req = Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": INSTALL_V1_ACCEPT,
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        if e.code == 404:
            return name, None, None, "404"
        return name, None, None, f"http_{e.code}"
    except URLError as e:
        return name, None, None, f"url_{e.reason!s}"
    except (TimeoutError, OSError) as e:
        return name, None, None, str(e)

    modified = data.get("modified")
    latest: Optional[str] = None
    tags = data.get("dist-tags")
    if isinstance(tags, dict):
        lv = tags.get("latest")
        if isinstance(lv, str):
            latest = lv
    if isinstance(modified, str):
        return name, modified, latest, None
    return name, None, latest, "no_modified_field"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="List npm packages with registry modified time within the last N hours."
    )
    parser.add_argument(
        "--within-hours",
        type=float,
        default=24.0,
        help="Include packages with modified >= (now - this many hours). Default: 24.",
    )
    parser.add_argument(
        "--changes-limit",
        type=int,
        default=5000,
        help="Rows per _changes request (max ~10000). Default: 5000.",
    )
    parser.add_argument(
        "--max-batches",
        type=int,
        default=8,
        help="Max _changes pages to walk (newest-first). Default: 8.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=24,
        help="Parallel registry metadata fetches. Default: 24.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=45.0,
        help="HTTP timeout seconds. Default: 45.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write JSON array to this path (UTF-8).",
    )
    parser.add_argument(
        "--names-only",
        action="store_true",
        help="Print one package name per line (no JSON wrapper).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Less stderr logging.",
    )
    args = parser.parse_args()

    cutoff = _utc_now() - timedelta(hours=args.within_hours)
    user_agent = DEFAULT_UA

    seen_ids: set[str] = set()
    pending: list[str] = []
    since: Optional[int] = None
    batches_done = 0

    if not args.quiet:
        print(
            f"[i] Cutoff (UTC): {cutoff.isoformat()} "
            f"(within last {args.within_hours} h)",
            file=sys.stderr,
        )

    while batches_done < args.max_batches:
        batches_done += 1
        try:
            batch = fetch_changes_batch(
                descending=True,
                limit=max(1, min(args.changes_limit, 10_000)),
                since=since,
                user_agent=user_agent,
                timeout=args.timeout,
            )
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
            print(f"[!] _changes request failed: {e}", file=sys.stderr)
            return 2

        results = batch.get("results") or []
        if not results:
            if not args.quiet:
                print("[i] No more change rows.", file=sys.stderr)
            break

        seqs = [int(r["seq"]) for r in results if "seq" in r]
        min_seq = min(seqs) if seqs else None

        added = 0
        for row in results:
            pkg_id = row.get("id")
            if not isinstance(pkg_id, str) or not pkg_id:
                continue
            if pkg_id.startswith("_design"):
                continue
            if pkg_id in seen_ids:
                continue
            seen_ids.add(pkg_id)
            pending.append(pkg_id)
            added += 1

        if not args.quiet:
            print(
                f"[i] Batch {batches_done}: +{added} new names "
                f"(pending total {len(pending)}, since_next={min_seq})",
                file=sys.stderr,
            )

        # Next page: omit rows with seq <= min_seq from this batch (descending feed).
        if min_seq is not None and min_seq > 1:
            since = min_seq
        else:
            break

    if not pending:
        print("[!] No package names collected from _changes.", file=sys.stderr)
        return 1

    matches: list[dict[str, Any]] = []
    errors = 0

    def worker(nm: str) -> tuple[str, Optional[str], Optional[str], Optional[str]]:
        return fetch_modified_abbrev(nm, user_agent=user_agent, timeout=args.timeout)

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {pool.submit(worker, n): n for n in pending}
        for fut in as_completed(futures):
            name, modified_s, latest_v, err = fut.result()
            if err:
                errors += 1
                continue
            mod_dt = _parse_npm_time(modified_s or "")
            if mod_dt is None:
                errors += 1
                continue
            if mod_dt >= cutoff:
                spec = f"{name}@{latest_v}" if latest_v else name
                npm_web = f"https://www.npmjs.com/package/{quote(name, safe='')}"
                row = {
                    "name": name,
                    "version": latest_v,
                    "package_spec": spec,
                    "modified": modified_s,
                    "registry": _registry_package_url(name),
                    "npmjs": npm_web,
                }
                matches.append(row)

    matches.sort(key=lambda r: r.get("modified") or "", reverse=True)

    elapsed = time.perf_counter() - t0
    if not args.quiet:
        print(
            f"[i] Resolved {len(pending)} names in {elapsed:.1f}s; "
            f"{len(matches)} within window; {errors} fetch/skip issues.",
            file=sys.stderr,
        )

    if args.names_only:
        for m in matches:
            print(m.get("package_spec") or m["name"])
    else:
        print(json.dumps(matches, indent=2, ensure_ascii=False))

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(matches, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        if not args.quiet:
            print(f"[i] Wrote {len(matches)} records to {args.out}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
