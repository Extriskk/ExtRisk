# Bablu Review: VSCode Extension Vulnerable-Dependency Test (5 Fixtures)

**Purpose:** Share analyzer results from five test VSCode extensions that use known-vulnerable dependencies so Bablu can verify findings against the code and identify gaps or improvements in reports and dependency scanning.

**How to run (local unpacked extension):**
```bash
python src/analyzer.py test_fixtures/vscode_vuln_deps/<folder-name> --vscode --local
```

---

## 1. Test Extensions Overview

| Extension | Folder | Vulnerable dependency(ies) | Expected |
|-----------|--------|----------------------------|----------|
| test-ext-lodash | `test-ext-lodash` | lodash@4.17.4 (multiple GHSA) | High/Critical dep vulns |
| test-ext-minimist | `test-ext-minimist` | minimist@1.2.0 (prototype pollution) | High dep vulns |
| test-ext-axios | `test-ext-axios` | axios@1.5.0 (e.g. CVE) | High dep vulns |
| test-ext-json5 | `test-ext-json5` | json5@2.2.1 (e.g. prototype pollution) | High dep vulns |
| test-ext-multi | `test-ext-multi` | lodash@4.17.15 + minimist@1.2.0 | Multiple packages with vulns |

All fixtures live under `test_fixtures/vscode_vuln_deps/`. Each has a minimal `package.json`, `extension.js`, and `npm install` was run so `package-lock.json` and `node_modules` exist for the dependency scanner and OSV.

---

## 2. Analyzer Results Summary

| Extension | Risk score | Risk level | Supply chain score | Supply chain issues | BLUF (from HTML) |
|-----------|------------|------------|--------------------|---------------------|------------------|
| test-ext-lodash | 0.2/10 | MEDIUM | 1.5/2 | 8 | "8 dependency vulnerability(ies) in 1 package(s) detected in supply chain. Upgrade affected packages or conduct security review before use." |
| test-ext-minimist | 0.0/10 | LOW | 1.0/2 | 2 | (LOW verdict; dependency vulns present in JSON) |
| test-ext-axios | 0.7/10 | MEDIUM | 1.5/2 | 5 | (MEDIUM; dependency vulns + 1 code finding re: axios) |
| test-ext-json5 | 0.0/10 | LOW | 1.0/2 | 1 | (LOW verdict; dependency vuln present in JSON) |
| test-ext-multi | 0.2/10 | MEDIUM | 1.5/2 | 6 | (MEDIUM; multiple packages with vulns) |

- **Dependency vulns:** All five extensions had at least one `dependency_vulnerability` finding in `supply_chain.findings` and non-empty `supply_chain.dependency_vulns` in the JSON reports.
- **BLUF:** The lodash report HTML includes an explicit BLUF line about dependency vulnerabilities; the others may vary. Worth checking that every report with `dependency_vulns` has a BLUF line that mentions “dependency” or “supply chain” so reviewers see it immediately.
- **Risk level vs. vuln count:** minimist (2 high vulns) and json5 (1 vuln) received **LOW (0.0)** due to positive signals (no network, no obfuscation, etc.). So “vulnerable deps only” can still yield LOW. Consider whether a **minimum floor** when any high/critical dependency vuln exists would better reflect supply-chain risk for Bablu’s manual review prioritization.

---

## 3. Report Locations (for Bablu)

- **JSON (technical):**  
  `reports/vscode_test-publisher.test-ext-<name>_analysis.json`
- **HTML (professional):**  
  `reports/vscode_test-publisher.test-ext-<name>_threat_analysis_report.html`

Replace `<name>` with: `lodash`, `minimist`, `axios`, `json5`, `multi`.

**Key JSON paths for dependency review:**
- `supply_chain.findings` — each item can have `type: "dependency_vulnerability"`, `package`, `version`, `cve_id`, `link`, `detail`.
- `supply_chain.dependency_vulns` — list of `{ package, version, vulns: [{ id, link }] }`.

---

## 4. What to Check (Bablu)

1. **Cross-check code vs. report**
   - For each fixture, open the extension’s `extension.js` (and any other JS under the folder).
   - Confirm that the reported dependency names and versions match `package.json` and that the CVEs/GHSAs in the report apply to those versions (e.g. lodash 4.17.4, minimist 1.2.0, axios 1.5.0, json5 2.2.1).
   - Verify that “sensitive module usage” (e.g. axios in test-ext-axios) is consistent with actual `require('axios')` usage.

2. **BLUF and severity**
   - For every report that has `supply_chain.dependency_vulns` non-empty, confirm the HTML report has a clear BLUF line about dependency/supply-chain risk.
   - Note whether LOW risk for “vuln-only” extensions (minimist, json5) is acceptable or if the wording/score should be adjusted (e.g. “LOW but has known dependency vulnerabilities – upgrade recommended”).

3. **Missing or weak areas**
   - **IDs:** Are CVE IDs (e.g. CVE-2020-8203 for lodash) surfaced in addition to GHSA where applicable?
   - **Severity mapping:** Is “high” vs “critical” from OSV/advisory reflected in the report and in risk breakdown?
   - **Remediation:** Does the report or BLUF suggest “upgrade to fixed version” and, if easily available, the fixed version number?
   - **Multi-package:** For test-ext-multi, are both lodash and minimist vulns clearly listed and attributed per package?

4. **False positives**
   - These fixtures are minimal (no malicious code). Confirm there are no incorrect “malicious” or “behavioral” findings; only dependency and possibly benign “sensitive module” (e.g. axios) should appear.

---

## 5. Suggested Improvements (for analyzer / report)

- **BLUF:** Ensure every report with at least one dependency vulnerability has a BLUF line that explicitly mentions dependency/supply-chain risk and upgrade.
- **Risk floor:** Consider a rule: if any dependency has high/critical vuln, risk level is at least MEDIUM (or a minimum supply_chain component score) so “vuln-only” extensions don’t appear as LOW without a dependency caveat.
- **Remediation:** In the HTML/JSON, add “fixed version” or “upgrade to” when the vulnerability database provides it.
- **Regex warning:** Fix the startup warning: `Failed to compile pattern 'Fetch with credentials include (cookie replay)'` (nothing to repeat at position 0) so logs stay clean.

---

## 6. Quick Commands for Bablu

```bash
# Re-run analyzer on one fixture
python src/analyzer.py test_fixtures/vscode_vuln_deps/test-ext-lodash --vscode --local

# List generated reports
dir reports\vscode_test-publisher.test-ext-*

# Inspect dependency vulns in JSON (PowerShell)
Get-Content reports\vscode_test-publisher.test-ext-lodash_analysis.json | ConvertFrom-Json | Select -ExpandProperty supply_chain | Select -ExpandProperty dependency_vulns
```

After review, Bablu can note what’s missing and what should be improved in the dependency scan, risk scoring, and report content (BLUF, severity, remediation, and clarity for multi-package cases).
