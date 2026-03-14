# Project Overview

## Product Name
Browser & VSCode Extension Security Analyzer

## What this product does
A professional-grade security analysis platform that detects malicious browser extensions (Chrome, Edge) and VSCode extensions before installation. It combines static code analysis, behavioral correlation, taint tracking, dynamic runtime analysis, domain intelligence, file hash intelligence, and threat attribution to produce risk scores and detailed threat reports.

## Target Users
- Security teams evaluating extensions before enterprise deployment
- Security researchers analyzing malware campaigns
- Extension developers validating their own code
- Individual users checking extension safety

## Core Value Proposition
Catches sophisticated threats that simple pattern matching misses by correlating capabilities across permissions, code patterns, network behavior, and runtime signals into compound threat assessments. Produces analyst-grade reports with evidence and remediation guidance.

## Current Stage
Active development — V7 functional for Chrome/Edge/VSCode analysis with static + dynamic + threat intel + file hash VT + verified badge detection + trusted publisher classification (~75) + automated report validation.

## Tech Stack
- **Analysis Engine**: Python 3.10+ (regex, esprima AST, Shannon entropy, hashlib SHA-256)
- **Dynamic Analysis**: Playwright + Chrome DevTools Protocol (CDP)
- **Threat Intel**: VirusTotal API (domains + file hashes), domain intelligence, OSINT web search
- **Reports**: HTML (dark-theme professional), JSON (technical)
- **CLI**: argparse-based with --fast, --dynamic, --edge, --vscode, --local modes
- **Web UI**: FastAPI backend + HTML/JS frontend with progress bar

## Main Repositories / Folders
```
src/                          # Core analysis modules
  analyzer.py                 # Main orchestrator (Chrome/Edge pipeline)
  store_metadata.py           # Chrome Web Store metadata + verified badge detection
  static_analyzer.py          # Regex patterns + AST + permissions + file hashing + domain validation + trusted publishers
  ast_analyzer.py             # esprima AST; large-file skip, config cap, depth limit
  advanced_detection.py       # CSP manipulation, WebSocket C2, delayed activation
  enhanced_detection.py       # Wallet hijack, phishing, crypto theft
  taint_analyzer.py           # Source-sink data flow tracking
  network_capture.py          # Playwright dynamic analysis + CDP
  behavioral_engine.py        # Static behavioral correlation engine (18 rules)
  domain_intelligence.py      # Typosquatting, DGA, C2 pattern detection
  virustotal_checker.py       # VT domain reputation + file hash lookup
  threat_attribution.py       # Campaign matching + OSINT
  professional_report.py      # HTML report generator (file hash IOCs, top 5 domains)
  report_validator.py         # [V5] Automated "Bablu Review" — FP detection engine
  host_permissions_analyzer.py # Host permission categorization
  pii_classifier.py           # PII/data type classification
  false_positive_filter.py    # FP suppression logic + benign domain list (~75 domains)
  sensitive_target_detector.py # Email/finance/auth target detection
  campaign_detector.py        # Campaign fingerprinting (GhostPoster, PDF Toolbox, etc.)
  vscode_analyzer.py          # VSCode extension analyzer (separate engine)
  vscode_downloader.py        # VS Marketplace downloader
  vscode_unpacker.py          # VSIX unpacker
  vscode_html_analyzer.py     # VSCode HTML report generator
web/                          # Web UI
  app.py                      # FastAPI backend with background analysis + cancel
  templates/index.html        # Frontend: progress bar, recent scans (top 5)
test_fixtures/                # Test extensions
  malicious_test_extension/   # Chrome extension with sinkhole C2 (127.0.0.1) for rule-engine validation
reports/                      # Generated HTML/JSON reports (default: repo root)
docs/                         # ANALYSIS_CAPABILITIES.md, DETECTION_LIBRARY.md
data/                         # Downloaded extensions cache + extracted files + detection library
  extensions/                 # Extracted extension directories
  known_malicious_extensions.json  # Known malicious campaign IDs
  detection_artefacts.json    # Per-campaign detection artefacts
ai-context/                   # AI session context files
```
