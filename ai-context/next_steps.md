# Next Steps

## Completed
- [x] V5 File Hash VT Integration (SHA-256 hashing + VT lookup + critical risk floor + report IOC section) (2026-02-15)
- [x] V5 Domain FP Cleanup (CamelCase/TLD/namespace rejection in _is_plausible_host + _is_real_domain) (2026-02-15)
- [x] V5 JS Scan Scope (manifest-referenced + high-value filenames only) (2026-02-15)
- [x] V5 Unified Top 5 Domains (single sorted IOC block replacing 3 blocks) (2026-02-15)
- [x] V5 Report Validator — "Bablu Review" automated FP detection (2026-02-15)
- [x] V6 Store metadata, first-party, detection library, VK Styles, generic wording (2026-02-15)
- [x] Post-V6 Report quality: snippet caps, dedup (name,file,line), first-party→LOW, example.com benign, VT runtime filter, EXFIL-006 (2026-02-16)
- [x] V7 Hardening: trusted publisher expansion (75), benign domain expansion (75), supply chain safety fix (2026-02-16)
- [x] V7 Verified badge detection fix for new Chrome Web Store — embedded data array parsing (2026-02-16)
- [x] V7 Unit42 threat intel integration — GitHub IOC search (2026-02-16)
- [x] V11 Report quality 12-fix plan + OSV/Retire.js vuln enrichment + performance fixes (2026-02-21)
- [x] V12 Phase 1 MVP — API platform: FastAPI + PostgreSQL + Redis/RQ + Docker (2026-02-22)

## Immediate (Platform — Phase 2)
- [ ] **Version monitoring endpoint** — `POST /api/v1/monitor`: enable daily cron check for version changes, webhook alerts
- [ ] **Risk delta computation** — compare current vs previous scan: new permissions, new domains, new taint flows, score delta
- [ ] **Dashboard UI** — React/Next.js frontend for the API: scan submission, progress, report viewing, extension history
- [ ] **Domain filtering & External Communication section** — expand benign domain list, filter from report, add Koi-style External Communication section
- [ ] **Redis-backed rate limiting** — replace in-memory rate limiter with Redis counters

## Medium Priority (Detection Quality)
- [ ] **Implement FP fixes in detection engine** — Tighten patterns based on validator findings:
  - Keystroke Buffer Array: require nearby `addEventListener('keydown')` to count
  - Dynamic Function: whitelist webpack `new Function('return this')` polyfill
  - Chrome Storage Sync: only flag when paired with sensitive data sources
  - IndexedDB: only flag when paired with sensitive data access
  - Domain extraction: strip comments before FQDN regex, skip `.txt`/`.lst` filter rule files
  - VT 1-vendor detections: reduce penalty to +0.1 or skip
- [ ] **Re-run Urban AdBlocker** — Verify FP fixes reduced noise
- [ ] **Regression test benign extensions** — Bitwarden, uBlock Origin, React DevTools should score LOW/MINIMAL

## Long Term / Ideas
- **SaaS billing integration** — Stripe, usage-based pricing ($0.50-$2/scan, $49-$199/mo subscription)
- **API key management UI** — self-service key creation, usage dashboards
- **Compliance export** — SOC2, ISO27001 mapping for enterprise customers
- ML-based semantic code analysis
- Behavioral baselining over time (store results, alert on changes)
- OAuth scope analysis for extensions requesting Google/Microsoft tokens
- Forced execution via service worker context injection (FV8-lite)
- Clean up `# #region agent log` debug blocks from ast_analyzer.py and static_analyzer.py
