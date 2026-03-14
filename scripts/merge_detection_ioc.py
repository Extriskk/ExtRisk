from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Dict, Any


def normalize_json_quotes(raw: str) -> str:
    """
    The detection_ioc file uses curly quotes. Normalize them so json.loads works.
    """
    trans_table = str.maketrans(
        {
            "“": '"',
            "”": '"',
            "‘": "'",
            "’": "'",
        }
    )
    return raw.translate(trans_table)


def add_domains(
    domains: Dict[str, Any],
    domain_list: Iterable[str] | None,
    now_iso: str,
) -> None:
    """
    Add new domain entries into the IOC DB if they don't already exist.
    We mark them as MALICIOUS since they come from vetted threat intel feeds.
    """
    if not domain_list:
        return

    for d in domain_list:
        if not d:
            continue
        d = d.strip()
        if not d:
            continue
        if d in domains:
            continue

        domains[d] = {
            "domain": d,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "vt_detections": 0,
            "vt_vendors": [],
            "threat_level": "MALICIOUS",
            "reputation": 0,
            "extensions_using": [],
            "total_observations": 0,
        }


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    ioc_db_path = repo_root / "iocs.json"
    campaigns_path = repo_root / "reports" / "detection_ioc.txt"

    if not ioc_db_path.exists():
        raise SystemExit(f"IOC DB not found at {ioc_db_path}")
    if not campaigns_path.exists():
        raise SystemExit(f"Campaign IOC file not found at {campaigns_path}")

    raw = campaigns_path.read_text(encoding="utf-8")
    clean = normalize_json_quotes(raw)

    data = json.loads(clean)
    campaigns = data.get("campaigns", [])

    ioc_db = json.loads(ioc_db_path.read_text(encoding="utf-8"))
    domains: Dict[str, Any] = ioc_db.setdefault("domains", {})
    extensions: Dict[str, Any] = ioc_db.setdefault("extensions", {})

    now_iso = datetime.now(timezone.utc).isoformat()

    for campaign in campaigns:
        # Domain-level IOCs
        add_domains(domains, campaign.get("c2_domains"), now_iso)
        add_domains(campaign.get("c2_infrastructure", {}).values() if isinstance(campaign.get("c2_infrastructure"), dict) else [], [], now_iso)  # no-op but kept for future extension
        add_domains(domains, campaign.get("phishing_domains"), now_iso)

        additional = campaign.get("additional_iocs") or {}
        add_domains(domains, additional.get("squatting_domains"), now_iso)

        # Extension-level IOCs (Chrome only, since this repo focuses on Chrome)
        for ext in campaign.get("extensions", []):
            if ext.get("platform") != "Chrome":
                continue

            ext_id = ext.get("id")
            if not ext_id or ext_id in extensions:
                continue

            extensions[ext_id] = {
                "extension_id": ext_id,
                "name": ext.get("name", "Unknown"),
                "version": "Unknown",
                "risk_score": 10.0,
                "malicious_domains": [],
                "suspicious_patterns": [],
                "dangerous_permissions": [],
                "first_analyzed": now_iso,
                "last_analyzed": now_iso,
            }

    # Update metadata
    metadata = ioc_db.setdefault("metadata", {})
    metadata["last_updated"] = now_iso
    metadata["total_domains"] = len(domains)
    metadata["total_extensions"] = len(extensions)

    ioc_db_path.write_text(
        json.dumps(ioc_db, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        f"IOC DB updated from detection_ioc.txt — "
        f"{metadata['total_domains']} domains, {metadata['total_extensions']} extensions"
    )


if __name__ == "__main__":
    main()

