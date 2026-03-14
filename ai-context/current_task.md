# Current Task

## What we are working on right now
V12 — Extension Risk Intelligence Platform (Phase 1 MVP). Converting the CLI tool into an API-driven platform with PostgreSQL, Redis+RQ job queue, API key auth, structured REST endpoints.

## Why this matters
The tool currently works only via CLI. To become a SaaS product / SOC-integrated service, it needs a proper API layer with job queue, persistent storage, caching, and authentication. This is the foundation for version monitoring, risk delta detection, and enterprise integrations.

## V12 Tasks (Phase 1 MVP)

### API Platform Architecture
- [x] `api/config.py` — Environment-based config (DATABASE_URL, REDIS_URL, API keys, rate limits)
- [x] `api/database.py` — SQLAlchemy engine, session factory, `get_db()` dependency
- [x] `api/models.py` — ORM models: Extension, ScanJob, ScanResult (PostgreSQL)
- [x] `api/schemas.py` — Pydantic request/response schemas (AnalyzeRequest, JobStatus, ReportSummary, etc.)
- [x] `api/auth.py` — API key auth middleware (X-API-Key header, rate limiting)
- [x] `api/routes/analyze.py` — POST /api/v1/analyze, GET /api/v1/jobs/{id}, POST /api/v1/jobs/{id}/cancel
- [x] `api/routes/reports.py` — GET /api/v1/reports/{id}, GET /api/v1/reports/{id}/html, GET /api/v1/reports/{id}/full
- [x] `api/routes/extensions.py` — GET /api/v1/extensions/{id}, GET /api/v1/extensions/{id}/history
- [x] `api/main.py` — FastAPI app setup, CORS, lifespan (auto-create tables), route mounting
- [x] `api/worker.py` — RQ worker: dequeue job, run analyzer, store result, update DB
- [x] `docker-compose.yml` — PostgreSQL + Redis + API + Worker (2 replicas)
- [x] `Dockerfile` — Multi-stage build (Python + Node for Retire.js)
- [x] `alembic/` — Database migration setup
- [x] `.env.example` — Environment variable template
- [x] `requirements.txt` — Added psycopg2-binary, alembic, redis, rq

### Key Design Decisions
- Worker dispatches to `analyze_vscode_extension()` for VSCode, `analyze_extension()` for Chrome/Edge
- Version caching: SHA-256 hash of manifest/package.json; if unchanged, return cached ScanResult instantly
- Rate limiting: in-memory sliding window (Redis-backed in future)
- API key auth: dev mode (no keys configured) allows all requests
- Reports stored on disk (same `reports/` directory); paths saved in DB

## Files Created (V12 — 2026-02-22)

| File | Action | Description |
|------|--------|-------------|
| `api/__init__.py` | NEW | API package init |
| `api/config.py` | NEW | Environment config (DB, Redis, API keys, rate limits) |
| `api/database.py` | NEW | SQLAlchemy engine + session factory |
| `api/models.py` | NEW | Extension, ScanJob, ScanResult ORM models |
| `api/schemas.py` | NEW | Pydantic request/response schemas |
| `api/auth.py` | NEW | API key auth + rate limiting middleware |
| `api/main.py` | NEW | FastAPI app setup, CORS, route mounting |
| `api/worker.py` | NEW | RQ worker for async scan jobs |
| `api/routes/__init__.py` | NEW | Routes package |
| `api/routes/analyze.py` | NEW | /analyze and /jobs endpoints |
| `api/routes/reports.py` | NEW | /reports endpoints |
| `api/routes/extensions.py` | NEW | /extensions endpoints |
| `docker-compose.yml` | NEW | PostgreSQL + Redis + API + Worker |
| `Dockerfile` | NEW | Container build |
| `alembic.ini` | NEW | Alembic config |
| `alembic/env.py` | NEW | Alembic migration env |
| `.env.example` | NEW | Environment template |
| `requirements.txt` | MODIFIED | Added psycopg2-binary, alembic, redis, rq |
