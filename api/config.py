"""
Environment-based configuration for the Extension Risk Intelligence Platform.
All secrets and connection strings come from environment variables.
"""

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent.resolve()
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


class Settings:
    # Database: default to SQLite so local runs work without Postgres/psycopg2
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///api_local.db",
    )

    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # API keys (comma-separated list in env)
    API_KEYS: list[str] = [
        k.strip()
        for k in os.getenv("API_KEYS", "").split(",")
        if k.strip()
    ]

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
    SCAN_LIMIT_PER_DAY: int = int(os.getenv("SCAN_LIMIT_PER_DAY", "100"))

    # Worker
    QUEUE_NAME: str = os.getenv("QUEUE_NAME", "scans")
    JOB_TIMEOUT: int = int(os.getenv("JOB_TIMEOUT", "600"))  # 10 min

    # Reports storage
    REPORTS_DIR: Path = REPORTS_DIR

    # VirusTotal
    VT_API_KEY: str = os.getenv("VT_API_KEY", "")


settings = Settings()
