"""
One-off migration: copy Extension, ScanResult, ScanJob from SQLite to Postgres.

Usage:
  SOURCE_DATABASE_URL=sqlite:///./api_local.db DATABASE_URL=postgresql://... \\
    python scripts/migrate_sqlite_to_postgres.py
  python scripts/migrate_sqlite_to_postgres.py --source sqlite:///./api_local.db --target postgresql://...

Options:
  --truncate   Truncate target tables before copy (clean one-time migration).
  --no-migrate Skip running alembic upgrade head on target (use if schema already applied).

Run from repo root (with venv active). Requires psycopg2-binary for Postgres.
"""

import argparse
import os
import subprocess
import sys
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Import after path so api is available
from api.database import Base
from api.models import Extension, ScanJob, ScanResult

BATCH_SIZE = 50


def _coerce_uuids(model_class, row_dict):
    """Ensure UUID columns are uuid.UUID for Postgres (SQLite may give str)."""
    for col in model_class.__table__.columns:
        if col.type.python_type == uuid.UUID and col.key in row_dict:
            v = row_dict[col.key]
            if v is not None and isinstance(v, str):
                row_dict[col.key] = uuid.UUID(v)
    return row_dict


def _row_to_dict(row, model_class):
    """Build a dict of column names to values, excluding relationship state."""
    return {
        c.key: getattr(row, c.key)
        for c in model_class.__table__.columns
    }


def run_alembic_upgrade(target_url: str) -> None:
    env = {**os.environ, "DATABASE_URL": target_url}
    r = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        print(f"[!] Alembic upgrade failed: {r.stderr}")
        sys.exit(1)
    print("[+] Target schema up to date (alembic upgrade head)")


def truncate_target_tables(target_session):
    """Truncate in FK order: children first (scan_jobs, scan_results), then extensions."""
    for table in ("scan_jobs", "scan_results", "extensions"):
        target_session.execute(text(f"TRUNCATE TABLE {table} CASCADE"))
    target_session.commit()
    print("[+] Truncated target tables (scan_jobs, scan_results, extensions)")


def copy_table(
    source_session,
    target_session,
    model_class,
    order_by_col,
    batch_size=None,
    use_merge=True,
):
    """Copy all rows from source to target. Preserves PKs and FKs."""
    table_name = model_class.__table__.name
    q = source_session.query(model_class).order_by(order_by_col)
    total = 0
    batch = []
    for row in q:
        attrs = _row_to_dict(row, model_class)
        _coerce_uuids(model_class, attrs)
        batch.append(model_class(**attrs))
        total += 1
        if batch_size and len(batch) >= batch_size:
            for o in batch:
                if use_merge:
                    target_session.merge(o)
                else:
                    target_session.add(o)
            target_session.commit()
            print(f"    {table_name}: {total} rows...")
            batch = []

    for o in batch:
        if use_merge:
            target_session.merge(o)
        else:
            target_session.add(o)
    if batch:
        target_session.commit()
    print(f"[+] {table_name}: {total} row(s) copied")
    return total


def main():
    parser = argparse.ArgumentParser(
        description="Migrate local SQLite DB to Postgres (extensions, scan_results, scan_jobs)."
    )
    parser.add_argument(
        "--source",
        default=os.environ.get("SOURCE_DATABASE_URL", "sqlite:///api_local.db"),
        help="Source DB URL (default: SOURCE_DATABASE_URL or sqlite:///api_local.db)",
    )
    parser.add_argument(
        "--target",
        default=os.environ.get("DATABASE_URL"),
        help="Target Postgres URL (default: DATABASE_URL)",
    )
    parser.add_argument(
        "--truncate",
        action="store_true",
        help="Truncate target tables before copy (destructive; for clean one-time migration)",
    )
    parser.add_argument(
        "--no-migrate",
        action="store_true",
        help="Skip running alembic upgrade head on target",
    )
    args = parser.parse_args()

    if not args.target or not args.target.strip().lower().startswith("postgresql"):
        print("[!] Target must be a Postgres URL (set DATABASE_URL or use --target).")
        sys.exit(1)

    source_url = args.source.strip()
    if source_url.startswith("sqlite:///") and not source_url.startswith("sqlite:////"):
        # Relative path: resolve from repo root
        path = source_url.replace("sqlite:///", "")
        if not Path(path).is_absolute():
            source_url = f"sqlite:///{REPO_ROOT / path}"
    target_url = args.target.strip()

    print(f"[*] Source: {source_url.split('@')[-1] if '@' in source_url else source_url}")
    print(f"[*] Target: {target_url.split('@')[-1] if '@' in target_url else 'Postgres (hidden)'}")

    # SQLite connect args for FK and WAL
    source_connect_args = {}
    if "sqlite" in source_url:
        source_connect_args["check_same_thread"] = False
        source_connect_args["timeout"] = 30

    source_engine = create_engine(
        source_url,
        connect_args=source_connect_args,
    )
    target_engine = create_engine(
        target_url,
        pool_pre_ping=True,
    )

    SourceSession = sessionmaker(bind=source_engine, autocommit=False, autoflush=False)
    TargetSession = sessionmaker(bind=target_engine, autocommit=False, autoflush=False)

    if not args.no_migrate:
        run_alembic_upgrade(target_url)

    source_session = SourceSession()
    target_session = TargetSession()

    use_merge = not args.truncate
    if args.truncate:
        truncate_target_tables(target_session)

    try:
        # 1. extensions (no FKs)
        copy_table(
            source_session,
            target_session,
            Extension,
            Extension.id,
            use_merge=use_merge,
        )
        # 2. scan_results (FK to extensions)
        copy_table(
            source_session,
            target_session,
            ScanResult,
            ScanResult.scanned_at,
            batch_size=BATCH_SIZE,
            use_merge=use_merge,
        )
        # 3. scan_jobs (FK to extensions, optional FK to scan_results)
        copy_table(
            source_session,
            target_session,
            ScanJob,
            ScanJob.created_at,
            batch_size=BATCH_SIZE,
            use_merge=use_merge,
        )
        print("\n[i] Migration completed successfully.")
    except Exception as e:
        target_session.rollback()
        print(f"\n[!] Migration failed: {e}")
        sys.exit(1)
    finally:
        source_session.close()
        target_session.close()


if __name__ == "__main__":
    main()
