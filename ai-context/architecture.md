# Architecture

## High Level Flow

### Chrome/Edge Extension Analysis (9-step pipeline)
1. **Store Metadata** - Fetch from Chrome Web Store / Edge Add-ons (name, author, users, rating, warnings)
2. **Download** - Download .crx file from store
3. **Unpack** - Extract .crx to directory, read manifest.json
4. **Permissions Analysis** - Score individual permissions + host permission categorization + attack-path combinations
5. **Static Analysis** - Regex patterns + AST analysis (esprima) + taint tracking (source-sink flows) + file hashing
6. **Domain Intelligence** - Typosquatting, DGA detection, C2 patterns for all extracted URLs
7. **VirusTotal** - Domain reputation + file hash lookup against 90+ security vendors
8. **Dynamic Analysis** (optional) - Playwright loads extension, CDP captures network/console/WebSocket, behavioral convergence verdict
9. **Report Generation** - HTML (dark-theme professional) + JSON (technical data)

Between steps 6 and 7, additional detection passes run:
- Advanced Detection: CSP manipulation, DOM event injection, WebSocket C2, delayed activation, obfuscation
- Enhanced Detection: Wallet hijack, phishing overlays, crypto theft
- **Behavioral Correlation Engine**: Correlates all findings into compound threat patterns

### VSCode Extension Analysis (4-layer model)
1. **Metadata & Publisher** - VS Marketplace metadata, publisher verification, install count
2. **Supply Chain** - Dependencies, node_modules, bundled code analysis
3. **Deep Code Analysis** - 200+ patterns + 22 behavioral correlation rules + capability detection
4. **Risk Scoring** - Multi-component model (code + correlations + infrastructure + positive signals)

## Main Components

### 1) Extension Fetcher (`downloader.py`, `vscode_downloader.py`) + Store Metadata (`store_metadata.py`)
Downloads from Chrome Web Store, Edge Add-ons, or VS Marketplace. Handles CRX/VSIX formats.
- **Store metadata** fetches author, version, users, rating, featured, trader from Chrome Web Store (chromewebstore.google.com)
- **Verified badge detection** [V7]: `_detect_verified_badge()` parses embedded developer data array from CWS HTML. Developer data format: `["email", "address", null, VERIFIED_FLAG, null, "dev-id", "Dev Name"]` where `VERIFIED_FLAG = 1` means verified. 4 fallback strategies (embedded array → JSON-LD → DOM → text markers).
- **Developer info extraction** [V7]: Author name extracted from same embedded array as reliable fallback when DOM/regex parsing fails.

### 2) Static Analysis Engine (`static_analyzer.py`) + AST (`ast_analyzer.py`)
- **Regex patterns** across 16+ attack categories (credential theft, keylogging, screen capture, code injection, data exfiltration, obfuscation, fingerprinting, etc.)
- **AST analysis** via esprima: Tracks fetch/XHR destinations, data flow, config references
- **Permission scoring**: Individual + combination attack-path scoring
- **False positive reduction**: Comment skipping, library detection, first-party domain allowlisting (~70 domains), benign domain filtering (~75 domains)
- **Trusted publisher list** [V7]: ~75 publishers (browser vendors, security, cloud/SaaS, productivity, enterprise, web platforms). 3-way match: CWS verified badge OR full author name OR first-word match. Trusted → LOW risk cap (3.5), but cap skipped when critical findings exist (supply chain safety).
- **File hashing** [V5]: `_compute_file_hashes()` computes SHA-256 of security-critical files (manifest.json, manifest.js, background scripts, content scripts). Popup/web-accessible excluded — conserves VT API calls.
- **Domain validation** [V5]: `_is_plausible_host()` rejects CamelCase identifiers, known API namespace prefixes (30+), non-public TLDs, and single-label strings. Curated TLD set (~140 entries) used.
- **JS file selection** [V5]: `_prioritize_js_files_for_security()` only scans manifest-referenced files (background, content scripts, service worker) + high-value attacker filenames (inject.js, helper.js, payload.js, stealer.js, find-password.js, manifest.js). Libraries, polyfills, and framework code excluded.
- **Large-file / robustness:**
  - `node_modules` and `bower_components` excluded from both AST and pattern scan
  - **AST** (`ast_analyzer.py`): Files >1 MiB skip full AST; `_traverse_ast` max depth 10,000; config extraction capped at 512 KiB
  - **Pattern scan** (`static_analyzer.py`): `_read_file_cached` caps read at 1 MiB per file
- **Two-pass regex** [V3]: `_safe_pattern_finditer()` for patterns with `[\s\S]{0,N}` where N>=50. Two-pass anchor+tail matching in bounded window.
- **VT graduated threshold** [V3]: 5+ detections = +3.0, 3+ = +1.5, 1-2 = +0.5
- **Slice-safety & fallback scan** [V4]: `_safe_slice()`, `_safe_int()`; on exception, `_scan_code_minimal()` runs regex-only; `results['scan_coverage']` reports coverage.
- **Sinkhole detection** [V4]: `_detect_sinkhole_and_infra_signals()` detects localhost-only C2/exfil; sets `sinkhole_or_lab_c2`.
- **Infrastructure score** [V4]: Component 4 adds exfil count, WebSocket C2, beaconing signals.

### 3) Behavioral Correlation Engine (`behavioral_engine.py`)
Correlates findings from ALL analysis layers into 18 compound threat rules:
- Session theft chains (cookies + all_urls + network)
- Credential harvesters (password monitoring + POST exfil)
- Surveillance agents (keylogger + screen capture + network)
- Remote code execution (CSP removal + eval + external scripts)
- Wallet hijacking, phishing overlays, WebSocket C2
- Evasion-wrapped payloads, native system escape, OAuth theft
- Traffic MitM, extension manipulation, staged payloads
- Remote-Controlled Extension [V3]: Remote iframe C2 + all_urls detection

### 4) Dynamic Analysis (`network_capture.py`)
- Playwright launches Chrome with extension loaded
- CDP captures: network requests, WebSocket frames, console messages, responses
- Behavioral analysis: beaconing detection, post-navigation exfil, credential patterns
- Chrome API mocking: synthetic cookie/tab/history data via Proxy injection
- Canary token detection: synthetic session cookies monitored in outbound traffic
- Date.now() time manipulation: +30 days to trigger time-bomb payloads
- DOM mutation tracking: script injection, iframe insertion, event handler injection via CDP
- Chrome API call logging: Proxy-based interception of sensitive APIs
- Verdict system: CLEAN -> LOW_RISK -> SUSPICIOUS -> MALICIOUS (canary leak -> auto MALICIOUS)

### 5) Threat Intelligence
- **VirusTotal** (`virustotal_checker.py`): Domain reputation + file hash lookup [V5], 24h caching, rate limiting. File hashes cached with `file:` prefix.
- **Domain Intelligence** (`domain_intelligence.py`): Typosquatting (Levenshtein), DGA scoring, C2 patterns
- **Threat Attribution** (`threat_attribution.py`): Campaign matching, OSINT web search, Unit42 GitHub IOC search [V7]. Canonical DarkSpectre source: Koi Security blog.

### 6) Sensitive Target Detector (`sensitive_target_detector.py`) [V3]
Detects extensions targeting high-value services:
- 4 categories: email, productivity, finance, auth (with domain lists)
- Gmail-specific surveillance module detection (7 indicators)
- Risk multiplier: email -> 1.3x, Gmail module -> 1.4x, finance -> 1.3x, auth -> 1.2x

### 7) Campaign Fingerprinting (`campaign_detector.py`) [V3]
Generates fingerprints for malicious campaign clustering:
- Code hashes (normalized, lib-excluded), infrastructure fingerprint, capability fingerprint
- 3 built-in campaign signatures: GhostPoster, PDF Toolbox, Great Suspender

### 8) Report Generator (`professional_report.py`)
Dark-theme HTML reports with:
- Executive summary, risk score gauge, threat classification
- **File Hash IOCs (SHA-256)** [V5]: Each critical file's hash, VT status badges, VT links. MALICIOUS hits highlighted.
- **Top 5 Domains (sorted by threat score)** [V5]: Unified from all sources (VT, AST, code, manifest). Sorted by malicious vendor count + community negative votes.
- Scan coverage [V4], Sinkhole C2 section [V4]
- Risk score breakdown with 4-component bars
- Behavioral correlations with attack chain cards
- Permission attack paths visualization
- Attack narrative chain visualization (ACCESS -> COLLECT -> EXFILTRATE -> PERSIST)
- Sensitive target detection, campaign fingerprint
- Detailed findings with code snippets and evidence
- Domain intelligence, VirusTotal results
- Supply chain version diff
- Remediation recommendations

### 9) Report Validator (`report_validator.py`) [V5 — NEW]
Automated post-analysis validation ("Bablu Review"):
- Reads analysis JSON + actual extension source code
- Classifies each finding as TRUE_POSITIVE / FALSE_POSITIVE / NEEDS_REVIEW
- **FP detection categories**: Webpack globalThis, reflect-metadata keystroke, chrome.storage.sync settings, idb IndexedDB, credit card field targeting, prototype references, localStorage/tab.url low-severity, domains from code comments, domains from filter rule files (.txt/.lst), VT 1-vendor noise, behavioral chain FP propagation
- **Output**: Console summary + optional JSON report with per-extension and aggregate FP/TP rates
- **Usage**: `python report_validator.py --count 10 --json report.json`

## Analysis Pipeline (data flow)

```
Store Metadata -> Download .crx -> Unpack -> manifest.json
                                              |
                                    +---------+---------+
                                    |                   |
                             Permissions           File Hashing (SHA-256)
                                    |                   |
                             Static Analysis       VT File Hash Check
                             (regex + AST)              |
                                    |              Critical risk floor
                             Domain Intel               |
                                    |                   |
                             Advanced/Enhanced     VT Domain Check
                                    |                   |
                             Behavioral Corr.     Threat Attribution
                                    |                   |
                                    +---------+---------+
                                              |
                                    Risk Score Calculation
                                    (4-component model)
                                              |
                                    Report Generation
                                              |
                                    Report Validation (optional)
```

## Known Weak Spots (Updated)
1. **Static patterns miss novel malware** — Regex can't understand code semantics (mitigated by behavioral correlation)
2. **ML-based semantic analysis not implemented** — Would catch entirely novel attack patterns
3. **Full V8 forced execution not implemented** — FV8-style path exploration requires V8 modification
4. **38.4% FP rate** [V5] — The validator identified this; FP fixes are the next priority
5. **Static-only taint** — No runtime taint tracking, only esprima source->sink
