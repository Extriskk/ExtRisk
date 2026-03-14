# Decisions Log

## Decision Template
Date:
Decision:
Reason:
Alternatives considered:

---

## Decisions

### V12: API Platform — PostgreSQL + Redis/RQ Architecture
Date: 2026-02-22
Decision: Build the Extension Risk Intelligence Platform as a FastAPI REST API with PostgreSQL for persistence, Redis + RQ for async job processing, and API key authentication. Keep the existing `web/app.py` as legacy.
Reason: The user's business plan calls for a SaaS API platform. PostgreSQL provides relational persistence for extensions, jobs, and results. Redis/RQ is lightweight and fits the scan workload (10-60s per job, typically <100/day in MVP). FastAPI already in use. Docker Compose makes deployment simple.
Alternatives considered: Celery (heavier, more features than needed for MVP), in-process BackgroundTasks (existing web/app.py approach — no persistence, no scaling), serverless (Lambda/Cloud Run — harder to run 60s+ analysis jobs), MongoDB (less structured, SQL better for relational data like extension→job→result)

### V12: Version Caching via Manifest Hash
Date: 2026-02-22
Decision: Cache scan results by SHA-256 hash of manifest.json (or package.json for VSCode). If the hash matches the last scan, return the cached ScanResult without re-running analysis.
Reason: Extensions don't change between versions. Re-scanning the same version wastes compute and API quota (VT). Hashing the manifest is a fast proxy for "same version" — if the manifest changes, the extension changed.
Alternatives considered: Hash the entire extension package (slow for large extensions), use version string only (publisher could re-upload same version with different code), always re-scan (wasteful)

### V12: Worker Dispatch — Separate Methods for VSCode vs Chrome/Edge
Date: 2026-02-22
Decision: The RQ worker dispatches to `analyze_vscode_extension()` for VSCode extensions and `analyze_extension()` for Chrome/Edge. No unified method.
Reason: The analyzer already has two separate pipelines — Chrome/Edge uses download→unpack→static analysis, VSCode uses a 5-layer analysis with supply chain scanning. Forcing both into one method would require significant refactoring with no benefit.
Alternatives considered: Unified `analyze(id, type)` method (would require large refactor of analyzer.py internals)

### V5: File Hash Scope — Security-Critical Files Only
Date: 2026-02-15
Decision: Only hash manifest.json, manifest.js (if present), background scripts (MV2/MV3), and content scripts. Exclude popup scripts, options pages, and web-accessible resources.
Reason: From analyst ("Bablu") perspective — popup and options page JS rarely contain payloads. Background and content scripts are the primary attack surfaces. Hashing fewer files conserves VT API rate limit (4 requests/min on free tier).
Alternatives considered: Hash all JS files (wastes API), hash only manifest.json (misses actual payloads)

### V5: Domain Validation with TLD Set
Date: 2026-02-15
Decision: Use a curated set of ~140 valid public TLDs to validate extracted "domains." Reject strings whose last label is not in this set. Also reject CamelCase strings and known API namespace prefixes.
Reason: The regex `_QUOTED_FQDN_PATTERN` was matching JS identifiers like `Permissions.PermissionsAdded` and `InternalAnalytics.TrackEvent` — these have the same `word.word` structure as domains. Checking the last label against real TLDs eliminates these FPs without affecting real domain extraction.
Alternatives considered: Stronger regex (too complex, still fragile), DNS resolution for each candidate (slow, network-dependent), public suffix list library (heavyweight dependency)

### V5: Manifest-Only JS Scan Scope
Date: 2026-02-15
Decision: `_prioritize_js_files_for_security()` only scans manifest-referenced files + a small set of high-value attacker filenames. All other JS (libraries, polyfills, framework) is excluded.
Reason: Security analyst POV — attackers put payloads in files the manifest executes (background, content scripts). Scanning bundled libraries produces false positives (webpack polyfills, reflect-metadata) and slows analysis. High-value filenames (inject.js, payload.js, stealer.js) cover edge cases where payload isn't manifest-referenced.
Alternatives considered: Scan all JS with FP suppression (still slow), scan by size (doesn't correlate with malice)

### V5: Unified Top 5 Domains (Sorted by Threat Score)
Date: 2026-02-15
Decision: Replace 3 separate domain IOC blocks with one unified "Top 5 Domains" block sorted by malicious vendor count (primary) + community negative votes (secondary).
Reason: The previous layout dumped all domains across 3 sections (Malicious, Exfil, Code/Manifest) with much overlap and no prioritization. An analyst wants the most suspicious domains first, not all domains everywhere. Top 5 keeps the report concise.
Alternatives considered: Keep all 3 sections with deduplication (still noisy), show all domains sorted (too long for reports with 50+ domains)

### V5: Report Validator ("Bablu Review") Architecture
Date: 2026-02-15
Decision: Build as a standalone script (`report_validator.py`) that reads analysis JSON + extension source code, with 12+ FP check categories and TRUE_POSITIVE/FALSE_POSITIVE/NEEDS_REVIEW classification.
Reason: Manual review of even one extension (Urban AdBlocker) found 7/7 findings were FPs. Scaling this to every analyzed extension requires automation. The validator acts as a quality feedback loop for the detection engine — identifies which patterns need tightening.
Alternatives considered: Integrate into the main pipeline (too slow, changes analysis behavior), separate web dashboard (overengineered for current stage)

### V5: VT 1-Vendor Detection as Noise
Date: 2026-02-15
Decision: In the report validator, flag VT results with only 1 malicious vendor as FALSE_POSITIVE (below noise threshold). Threshold for NEEDS_REVIEW is 3+ vendors; TRUE_POSITIVE is 5+ vendors.
Reason: VirusTotal has 90+ vendors; a single vendor flagging a domain is more likely a false positive or over-aggressive heuristic than a real threat. Urban AdBlocker had domains with 1/94 detections that were clearly benign.
Alternatives considered: Trust all VT results equally (too many FPs), ignore VT entirely for domains (loses real signal)

### V7: Supply Chain Safety — Skip Trusted Publisher Cap on Critical Findings
Date: 2026-02-16
Decision: The trusted publisher 3.5 risk cap now only applies when `crit_count == 0 AND bc_crit == 0 AND no malicious VT file hash`. If any critical finding exists, the cap is skipped and the malice floor stands.
Reason: A supply chain attack could compromise a trusted publisher's extension (e.g., malicious code injected into a Google extension). Without this safety check, the 3.5 cap would override the critical risk floor, hiding the compromise. The fix ensures that compromised trusted extensions still get flagged as HIGH/CRITICAL.
Alternatives considered: Remove the 3.5 cap entirely (too aggressive, real trusted extensions would score higher), only check VT hash (misses code-based critical findings)

### V7: Verified Badge via Embedded Data Array (Not DOM)
Date: 2026-02-16
Decision: Parse the Chrome Web Store embedded developer data array to detect the verified badge. Format: `["email", "address", null, VERIFIED_FLAG, null, "dev-id", "Dev Name"]` where `VERIFIED_FLAG = 1`. Fall back to JSON-LD, DOM, and text markers.
Reason: The new CWS (chromewebstore.google.com) is a SPA — the old store's CSS class `verified` doesn't exist. The SPA embeds data in serialized arrays within the HTML. `requests.get` returns the shell HTML with these arrays, but no rendered DOM. Parsing the array is the only reliable method without a headless browser.
Alternatives considered: Headless browser rendering (slow, heavy dependency), Chrome Web Store API (no public API for verified status), DOM parsing only (doesn't work on SPA shell)

### V7: Trusted Publisher List — 75 Publishers
Date: 2026-02-16
Decision: Expand from 26 to ~75 trusted publishers covering security vendors, cloud/SaaS, productivity, enterprise, and web platforms. All publishers chosen have verified Chrome/Edge extensions.
Reason: 26 publishers only covered browser vendors and a few big names. Major security companies (Norton, McAfee, Kaspersky), cloud providers (AWS, Salesforce), and popular platforms (Spotify, Reddit, PayPal) were missing. Their extensions were scoring MEDIUM+ unnecessarily.
Alternatives considered: Dynamic publisher verification via CWS API (no public API), smaller curated list (too many missing), trust any verified publisher (too broad — verification doesn't guarantee safety)

---

## Previous Decisions

### V4: Sinkhole C2 and Rule-Engine Validation Wording
Date: 2026-02-14
Decision: When all C2/exfil endpoints are localhost, classify as sinkhole and label as "sinkhole domains used only to validate the rule engine, not real C2."
Reason: Test extensions use 127.0.0.1 to validate detection rules; reports must not imply real C2.

### V4: Canonical Threat Intel for DarkSpectre
Date: 2026-02-14
Decision: Use canonical DarkSpectre blog as primary source; filter awesome-BrowserRelated and similar aggregators.
Reason: Attribution was citing non-primary sources.

### V3: Two-Pass Regex for Catastrophic Backtracking
Date: 2026-02-13
Decision: Split patterns with `[\s\S]{0,N}` (N>=200) into anchor+tail in bounded window.
Reason: Large JS files trigger exponential backtracking.

### V3: VirusTotal Graduated Threshold
Date: 2026-02-13
Decision: 5+ detections = +3.0, 3+ = +1.5, 1-2 = +0.5.
Reason: Domains like fb.me get 1-2 detections from URL shortener classification.

### V3: Sensitive Target Detection as Separate Module
Date: 2026-02-13
Decision: Create `sensitive_target_detector.py` with domain matching and Gmail module detection.
Reason: Runs early (Step 2.6) before static analysis; needs separate risk multiplier.

### V3: Campaign Fingerprinting with Built-in Signatures
Date: 2026-02-13
Decision: Fingerprint via normalized code hashes + domain hash + technique hash. 3 built-in signatures.
Reason: Known malicious patterns recur across extensions.

### Static Analysis: Large-File and Hang Hardening
Date: 2026-02-12
Decision: AST caps (1 MiB file, 512 KiB config, 10k depth), pattern cap (1 MiB), exclude node_modules.
Reason: Large extensions caused analysis to hang.

### Browser Analyzer: Risk Scoring V2 — 4-Component Model
Date: 2026-02-09
Decision: permissions (0-2.5) + code (0-2.5) + behavioral (0-3.0) + infrastructure (0-2.0).
Reason: Old model maxed patterns at 1 point.

### Browser Analyzer: Behavioral Engine as Separate Module
Date: 2026-02-09
Decision: Create `behavioral_engine.py` standalone.
Reason: Browser analysis has more data sources to correlate.

### Browser Analyzer: Canary Token Design
Date: 2026-02-09
Decision: Inject synthetic session cookies and monitor outbound traffic.
Reason: Static analysis identifies capability, not intent. Canary proves actual theft.

### Browser Analyzer: Time Manipulation for Forced Execution
Date: 2026-02-09
Decision: Override Date.now() +30 days during dynamic analysis.
Reason: 2,899 extensions hide behind time-bomb conditionals per FV8 research.
