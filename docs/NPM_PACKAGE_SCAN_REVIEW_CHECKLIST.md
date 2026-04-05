# npm package scan integration — security & architecture review checklist

This document supports **human review** and **LLM-assisted gap analysis** for the npm-mal-scan path (`src/npm_mal_scan_service.py`, `src/npm_mal_scan_runner.py`, `api/routes/npm_analyze.py`, `api/worker.py`, `api/npm_scan_finalize.py`, `api/routes/web.py`).

## Threat model (what we assume)

- **Untrusted input**: `package_spec` from API clients and the public `/app` form.
- **Trusted**: npm-mal-scan repo layout under `tools/npm-mal-scan` / `NPM_MAL_SCAN_ROOT` (supply chain of that tool is out of scope here).
- **Goals**: no shell/command injection, no path escape from `reports/npm_packages/`, bounded memory/DB use from huge scanner output, safe HTML when reports are served.

## Validation rules (`validate_npm_package_spec`)

When reviewing or extending validation, ensure:

1. **Single-line** spec; reject NUL, CR/LF, and most C0 controls.
2. **No URL / path abuse**: reject `://`, leading `/` or `\`, `..`, `%` in the package segment, backslashes.
3. **No obvious shell metacharacters** in the full spec: `;` `&` `` ` `` `$` (defense in depth; subprocess uses `shell=False`).
4. **Package vs version split** matches npm scoped rules (`@scope/name@version` vs `name@version`); reject `@scope` without `/`.
5. **Spaces** only allowed in the **version/range** segment, not in the package name.
6. **Length caps**: full spec ≤ 256 chars; version segment ≤ 512 chars.
7. **Normalization**: registry IDs use `npkg:` + lowercase spec; CLI argv uses the normalized spec.

**LLM gap-hunt prompts**: “Find inputs that pass validation but break `relative_to`”, “Find semver / npm aliases that users expect but validation rejects”, “Find Unicode or homoglyph bypasses of the ASCII regexes”.

## Subprocess contract

- **argv list only** — never interpolate into a shell string (`npm_mal_scan_runner.run_npm_mal_scan_captured`).
- **`stdin=DEVNULL`** — scanner cannot read sensitive stdin.
- **Timeout** — `JOB_TIMEOUT` / caller-provided cap.
- **One positional spec** — forward a single string argument as the scanner expects.

**Gaps to re-check when upgrading npm-mal-scan**: new CLI flags, subcommands, or env vars that change behavior.

## Filesystem safety

- Reports written only under `reports_dir.resolve() / "npm_packages" / <sanitized>`.
- After `resolve()`, paths must satisfy `sub.relative_to(base_dir)`; otherwise the scan fails closed.

**LLM gap-hunt**: “Can `spec_to_reports_dir_name` produce `..` segments or symlink tricks on Windows vs POSIX?”

## Output handling

- **Truncation** before JSON parse and disk write (`_MAX_STORED_STDOUT_CHARS`, `_MAX_STORED_STDERR_CHARS`).
- **JSON parse** only if stdout length ≤ `_MAX_JSON_PARSE_INPUT_CHARS` (mitigate parse bombs / huge allocations).
- **HTML report**: dynamic content goes through `html.escape`.

## Risk scoring (`_risk_from_parsed`)

- Heuristic mapping from optional JSON fields (`riskScore`, `findings`, …) and exit code.
- **Semantic coupling**: if npm-mal-scan changes exit-code meaning, risk levels may be wrong (document in scanner changelog).

**LLM gap-hunt**: “List cases where exit code 0 still indicates compromise” / “False calm when stdout is not JSON”.

## Architecture

- **Single finalize path**: `api/npm_scan_finalize.commit_npm_scan_to_job` — worker and API sync handler must not duplicate ScanResult field logic.
- **Jobs**: `browser_type == "npm"` and `extension_id` prefix `npkg:`; worker re-validates spec before running.
- **Web**: unauthenticated `/app/npm/analyze` — same abuse surface as extension analyze; rely on platform rate limits / WAF in production.

## Detection coverage (scope)

- **In scope**: whatever **npm-mal-scan** implements (typosquatting, install scripts, suspicious deps, etc. — see that project).
- **Out of scope in this integration**: OSV/Retire.js parity with VSCode extension pipeline, VirusTotal on tarball URLs, typosquat rules duplicated in Python.

**LLM gap-hunt**: “Compare VSCode `dependency_vuln_scanner` + Retire.js coverage to npm-mal-scan; list gaps.”

## Suggested regression tests (if you add a test suite)

- Valid: `lodash@4.17.21`, `@types/node@20.1.0`, `left-pad` (no version).
- Reject: `foo;curl`, `foo|bar`, `` foo`bar` ``, `foo$(x)`, `../x`, `https://evil/pkg`, `@scope` (no slash), `foo bar@1.0`.
- Path: mock `reports_dir` and assert resolved output stays under `npm_packages`.

---

*Keep this file updated when validation, caps, or job semantics change.*
