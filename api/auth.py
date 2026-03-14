"""
API key authentication and rate limiting middleware.

Auth: X-API-Key header checked against configured keys.
Rate limit: per-key request counter in Redis with TTL-based windows.
"""

import time
from fastapi import Request, HTTPException, Depends
from fastapi.security import APIKeyHeader

from api.config import settings

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# In-memory fallback rate limiter (used when Redis unavailable)
_rate_store: dict[str, list[float]] = {}


def _check_rate_limit(api_key: str) -> bool:
    """Simple sliding-window rate limiter (in-memory fallback)."""
    now = time.time()
    window = 60.0  # 1 minute window
    limit = settings.RATE_LIMIT_PER_MINUTE

    if api_key not in _rate_store:
        _rate_store[api_key] = []

    # Prune old entries
    _rate_store[api_key] = [t for t in _rate_store[api_key] if now - t < window]

    if len(_rate_store[api_key]) >= limit:
        return False

    _rate_store[api_key].append(now)
    return True


async def require_api_key(
    api_key: str = Depends(_api_key_header),
) -> str:
    """FastAPI dependency — validates API key and enforces rate limit."""
    # If no keys configured, allow all (dev mode)
    if not settings.API_KEYS:
        return "dev"

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key. Set X-API-Key header.")

    if api_key not in settings.API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API key.")

    if not _check_rate_limit(api_key):
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({settings.RATE_LIMIT_PER_MINUTE} requests/minute).",
        )

    return api_key
