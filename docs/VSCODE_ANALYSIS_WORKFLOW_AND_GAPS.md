# VSCode Extension Analysis: Workflow Alignment & Gaps

This document aligns the analyzer with a manual Phase 2–7 triage workflow, notes what was fixed, and gives Bablu a research checklist for further improvements.

---

## 1. Install (for users running the analyzer)

```bash
pip install -r requirements.txt
npm install
```

- **Retire.js** is included via `package.json` (`npm install`). The analyzer runs the **bundled JS scan** whenever it analyzes a VSCode extension (it uses `retire` from PATH or `node_modules/.bin/retire` / `npx retire` from repo root).
- When **auditing third-party extensions** (e.g. unpacked VSIX or cloned repo), run `npm install --ignore-scripts` in that extension folder to avoid executing potentially malicious `postinstall` / `preinstall` scripts while still resolving dependencies for the scanner.

---

## 2. What the analyzer does vs manual workflow

| Phase | Manual step | Analyzer coverage |
|-------|-------------|-------------------|
| **2. Initial triage** | Open package.json | ✅ package.json + deep inspection |
| | Verified publisher? | ✅ Marketplace metadata, `unverified_publisher` finding |
| | GitHub repo present? | ✅ `package_json_deep`: finding when repository missing |
| | Last update date? | ✅ Marketplace metadata (when using download flow); can be surfaced in report |
| | Install count low? | ✅ `low_adoption` risk signal |
| | Repo stars vs installs | ❌ Not implemented (marketplace doesn’t expose stars the same way) |
| | **Activation events** (*, onStartupFinished, workspaceContains, onCommand, onDebug) | ✅ `RISKY_ACTIVATION_EVENTS` + severity (high for *, onStartupFinished, onDebug) |
| | **Contributes** (terminal, tasks, debug, authentication, webview, filesystem) | ✅ `SENSITIVE_CONTRIBUTIONS`: terminal, taskDefinitions, tasks, debuggers, authentication, customEditors, viewsContainers, fileSystemProvider |
| **3. Supply chain** | npm install --ignore-scripts, npm list | ⚠️ We use existing package.json + lockfile; doc recommends --ignore-scripts for manual audits |
| | osv-scanner / snyk / retire | ✅ OSV API (declared/transitive) + Retire.js (bundled JS) |
| | Bundled deps (dist/, out/) | ✅ Retire scans full extension dir (including dist/out/) |
| **4. Static hunting** | child_process, exec, spawn, eval, new Function, vm | ✅ Code patterns for exec/spawn/eval/Function/vm |
| | Network (fetch, axios, http) | ✅ Network patterns + module usage |
| | Data exfil (.ssh, .git, token, credential, env) | ✅ Credential/sensitive path patterns |
| | Obfuscation (atob, Buffer.from, base64) | ✅ Patterns in code analysis |
| **5. VS Code specific** | createWebviewPanel, registerCommand, createTerminal | ✅ Patterns + behavioral correlations |
| **6. Dynamic** | VM/sandbox, mitmproxy | ✅ Optional Playwright-based network capture |
| **7. Risk scoring** | Custom weights (startup +3, child_process +3, …) | ✅ Restructured: vuln deps → 5/10 supply chain; rest 5 from metadata/code/behavior/infra; vuln floor = MEDIUM |

---

## 3. Fixes applied in this pass

- **Retire.js:** Added to project via `package.json`; scanner uses PATH or repo `node_modules`/npx so bundled JS scan runs whenever the analyzer runs on a VSCode extension.
- **Activation events:** Added `workspaceContains`, `onCommand`, `onDebug`; `onStartupFinished` and `onDebug` treated as high impact (same as `*`).
- **Contributes:** Added `taskDefinitions`, `tasks`, `customEditors`, `viewsContainers`, `fileSystemProvider` with risk descriptions.
- **Transparency:** Deep package.json check for missing `repository` → low-severity finding.
- **Scoring:** Vulnerable dependency (or bundled JS vuln) → supply chain 5/10 and at least MEDIUM; remaining 5 points from metadata, code, behavioral, infrastructure.
- **Docs:** README and requirements.txt mention `npm install` for VSCode; this doc adds `npm install --ignore-scripts` for safe auditing of third-party extension folders.

---

## 4. Bablu research: what else can be fixed

After the above fixes, consider:

1. **Last update / abandonment**
   - Surface “last updated” from marketplace in the VSCode report (and optionally a “possibly abandoned” hint if older than e.g. 2 years).

2. **Repo stars vs installs**
   - If we can get repo URL from package.json, we could (optionally) query GitHub API for stars and compare to install count as a sanity check (rate limits and token apply).

3. **npm install --ignore-scripts in analyzer**
   - When analyzing a **local** extension dir that has package.json but no node_modules (or stale), we could run `npm install --ignore-scripts` in that dir before OSV/Retire so dependency resolution is complete without executing lifecycle scripts. Today we assume the user has already run npm install.

4. **CVE tags in dependency findings**
   - Tag dependency/bundled vulns with categories (e.g. “prototype pollution”, “RCE”, “command injection”) when OSV/Retire provide them so reports can filter by “RCE” or “prototype pollution”.

5. **Snyk as second source**
   - Optional second dependency scanner (Snyk) for declared deps when API key is configured; compare with OSV to reduce false negatives.

6. **createWebviewPanel + remote HTML**
   - Explicit “webview loads remote HTML/JS” finding when we detect createWebviewPanel with non-data URI or non-local path (phishing/XSS risk).

7. **User input → exec()**
   - Stronger “command injection” correlation when we see registerCommand plus user input flowing into exec/spawn (already partially covered; tighten evidence and BLUF).

8. **Obfuscation severity**
   - Ensure “obfuscation” and “eval(atob(” style patterns consistently contribute to risk (e.g. in the “rest 5” code/behavior components) and appear in the report.

9. **Positive signals vs vuln floor**
   - With vuln floor at 5/10 MEDIUM, positive signals (no network, no obfuscation, etc.) can still reduce the score; confirm that we never show “LOW” when there is any high/critical dependency or bundled JS vuln (already enforced; keep in mind for future tweaks).

10. **Retire.js JSON format**
    - Retire’s JSON output can vary by version; if a Retire upgrade breaks parsing, add a version check or more defensive parsing and/or document the tested Retire version.

---

## 5. References

- Manual workflow (Phase 2–7): user-provided checklist (activation events, contributes, supply chain, static hunting, VS Code abuse patterns, risk scoring).
- Analyzer: `src/vscode_analyzer.py`, `src/retirejs_scanner.py`, `src/dependency_vuln_scanner.py`, `docs/ARCHITECTURE_DEPENDENCY_SCANNING_AND_PATTERNS.md`.
- Bablu: `docs/BABLU_REVIEW_VSCODE_VULNERABLE_DEPS.md`, `.cursor/skills/bablu/SKILL.md`.
