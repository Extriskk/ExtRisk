# Bablu Detection Library Review

**Purpose:** Review the VSCode/Chrome extension detection pattern library, compare with known threats and research, and list missing patterns and enhancements.  
**Reviewer:** Bablu workflow (extension JS analysis + scan result comparison).  
**Last updated:** 2026-02-19

---

## 1. Current Coverage Summary

The VSCode analyzer (`src/vscode_analyzer.py`) combines **20+ pattern sets** into `all_patterns`:

| Pattern set | Category examples | Purpose |
|-------------|-------------------|---------|
| COMMAND_INJECTION_PATTERNS | command_injection | child_process.exec/spawn, shell:true, Tasks API |
| UNSAFE_CODE_PATTERNS | code_execution | eval, new Function, vm, setTimeout(string) |
| SENSITIVE_PATH_PATTERNS | credential_theft, settings_theft, reconnaissance | SSH keys, .env, .git/config, homedir |
| NETWORK_PATTERNS | network_exfil | POST with data, WebSocket, encoded URL, IP connection |
| VSCODE_API_ABUSE_PATTERNS | terminal_hijack, data_access, webview_risk, command_uri | Terminal, workspace, clipboard, enableScripts, command: URI |
| OBFUSCATION_PATTERNS | obfuscation | Hex/unicode escapes, base64 blocks, control flow flattening |
| WEAK_CRYPTO_PATTERNS | weak_crypto | MD5, SHA1, DES/RC4, hardcoded IV/key |
| PROTOTYPE_POLLUTION_PATTERNS | prototype_pollution | __proto__, Object.assign, constructor.prototype |
| WORKSPACE_HARVESTING_PATTERNS | workspace_harvesting | Recursive read, bulk file, workspace folder enum |
| BASE64_EXFIL_PATTERNS | base64_exfil | Base64 encode, webview postMessage with base64 |
| DOCUMENT_MONITORING_PATTERNS | document_monitoring | Active editor, onDidChange, long setTimeout |
| WORKSPACE_ACTIVITY_PATTERNS | workspace_activity_monitoring | onDidOpen, onWillSave, folder change, fsPath |
| HTTP_ENDPOINT_PATTERNS | insecure_endpoint, localhost_access | Plaintext HTTP, suspicious TLD, axios+auth, localhost |
| TELEMETRY_ABUSE_PATTERNS | telemetry_abuse | Fingerprinting, machineId, analytics SDKs |
| VSCODE_API_EVASION_PATTERNS | (multiple) | OAuth theft, openExternal, ShellExecution, tasks, sendSequence, globalState |
| INDIRECT_CODE_EXECUTION_PATTERNS | code_execution | (0,eval), Function(), Reflect, dynamic import, vm.compileFunction |
| EVASION_FILE_ACCESS_PATTERNS | workspace_harvesting | createReadStream, fs.promises, homedir credential path |
| EVASION_NETWORK_PATTERNS | network_exfil | Discord webhook, Telegram, ngrok, pastebin, node: imports |
| EVASION_OBFUSCATION_PATTERNS | obfuscation | fromCharCode, join, Buffer.from, XOR decode, hex encode |
| EVASION_FINGERPRINT_PATTERNS | (fingerprinting) | CPU, network/MAC, memory, process env, process.memoryUsage |
| MODULE_ALIASING_PATTERNS | evasion_technique | Destructured exec, computed child_process, shell:!0, .call/.apply |
| CAPABILITY_PATTERNS | clipboard, terminal, local_server, identity_harvesting, remote_orchestration | Clipboard read/write, hidden terminal, HTTP server, GitHub API, /api/action |

Behavioral correlation rules then combine multiple findings (e.g. wildcard activation + process execution, file monitoring + base64 + network).

---

## 2. Gaps vs Known CVEs and Research

| CVE / Threat | What the extension does | Current detection | Gap |
|--------------|--------------------------|-------------------|-----|
| **CVE-2025-65716** (Markdown Preview Enhanced) | Crafted markdown runs JS in preview iframe; localhost port scan / exfil | Known vulnerable extension (metadata); enableScripts; webview innerHTML in app code | **Preview XSS** heuristic: innerHTML + user-controlled content in same file (e.g. webview/preview path) could be elevated or tagged. |
| **CVE-2025-65717** (Live Server) | Localhost dev server no CORS → remote page can crawl/exfil files | Known vulnerable; local_server patterns | Local server + listen on 0.0.0.0 could be correlated with “remote access”. |
| **CVE-2025-65715** (Code Runner) | executorMap from settings passed to child_process.spawn(..., { shell: true }) | Known vulnerable; executorMap pattern; command_injection | Strong coverage. |
| **CVE-2024-43488** (Arduino) | Missing auth on critical functionality → RCE | Known vulnerable | No generic “unauthenticated HTTP/WebSocket handler” pattern. |
| **Wallet / crypto theft** | clipboard + replace for wallet addresses | Behavioral: clipboard + crypto patterns | Chrome-focused; VSCode could add clipboard write + crypto/ethereum/solana string. |
| **Data exfil to C2** | fetch/XHR POST to remote URL with sensitive data | network_exfil, base64_exfil, correlations | Good. Could add **Slack/Discord webhook with file/content** as explicit pattern. |
| **Port scan from preview** | localhost fetch in webview/preview context | localhost_access | Could **correlate** localhost_access + webview/preview path for “port scan from preview” narrative. |

---

## 3. Missing Patterns (Recommended Additions)

- **Preview / webview XSS (app code only)**  
  - **Condition:** File under `webview/` or `preview/` (not under `dependencies/` or `node_modules`) AND (`.innerHTML` assignment OR `document.write`) AND (receives content from `postMessage` / `getState` / `document.uri` / markdown or HTML from API).  
  - **Action:** New category `preview_xss` or elevate severity of existing webview_risk when path is app preview and evidence suggests user-controlled content.  
  - **Rationale:** Directly maps to CVE-2025-65716-style issues.

- **Unauthenticated HTTP/WebSocket server**  
  - **Pattern:** `createServer` / `http.Server` or WebSocket server creation WITHOUT nearby `auth` / `token` / `session` / `verify` in same file or adjacent.  
  - **Action:** New category `unauthenticated_server` (medium) or correlation with local_server.  
  - **Rationale:** CVE-2024-43488 and similar “exposed local server” issues.

- **Slack/Discord webhook with file or large body**  
  - **Pattern:** URL containing `hooks.slack.com` or `discord.com/api/webhooks` AND (multipart/form-data, file read, or large JSON body).  
  - **Action:** Extend network_exfil or add `webhook_exfil`; severity high.  
  - **Rationale:** Common exfil channel; already have “Discord webhook” but can make “with file/content” explicit.

- **command: URI in webview HTML**  
  - **Pattern:** In .html or embedded HTML string: `command:` or `vscode-command:` in href/onclick.  
  - **Action:** Ensure existing command_uri pattern runs on HTML; add HTML analyzer rule if not.  
  - **Rationale:** Click in webview can run arbitrary VSCode commands.

- **Port-scan-from-preview correlation**  
  - **Condition:** localhost_access finding in a file whose path contains `webview` or `preview`.  
  - **Action:** Behavioral correlation: “Potential port scan from preview (CVE-style)”.  
  - **Rationale:** Surfaces CVE-2025-65716-style impact in report.

- **Settings/workspace path + network in same file**  
  - **Pattern:** Same file uses both (getConfiguration / workspace path / env) and (fetch/axios/XHR with non-constant URL).  
  - **Action:** Correlation “Config or workspace data may be sent to remote server”.  
  - **Rationale:** Data exfil from settings or workspace.

---

## 4. Enhancements Already Done (Reference)

- **child_process.exec:** Only match `child_process.exec(`, not bare `exec(` (avoids regex `.exec()` FP).
- **Webview innerHTML in dependencies:** Tagged with path_type; suppressed in report; app code only for high severity.
- **Plaintext HTTP:** Namespace URLs (w3.org, schemas, xmlns, etc.) excluded.
- **OAuth/identity:** Pattern tightened to accessToken/access_token/oauthToken/getToken/Bearer/session.token/credential (no bare `.token`).
- **path_type:** Every code finding has `path_type`: `app` | `dependency` for filtering and scoring.

---

## 5. Recommended Implementation Order

1. **Port-scan-from-preview correlation** – Use existing localhost_access + path; add one correlation rule.
2. **Preview XSS heuristic** – In _scan_patterns or _filter: for webview_risk in path containing `webview` or `preview` (and not dependency), optionally set category to `preview_xss` or severity critical when evidence suggests user content.
3. **command: URI in HTML** – Verify HTML analyzer scans for `command:` / `vscode-command:`; add if missing.
4. **Unauthenticated server** – New pattern or correlation: local_server without auth/token/session in same file.
5. **Webhook exfil** – Extend or add pattern for Slack/Discord webhook + file/large body.
6. **Settings/workspace + network correlation** – One new correlation rule.

---

## 6. Chrome vs VSCode

- **Chrome:** Permissions (cookies, webRequest, <all_urls>) drive risk; patterns in `static_analyzer.py` (manifest, content scripts, background). Taint and domain intel are key.
- **VSCode:** No manifest permissions; risk from activation events, dependencies, and code (Tasks, Terminal, webview, workspace). Dependency CVE scan and path_type (app vs dependency) are most impactful.
- Shared needs: fewer FPs in minified/lib code (path_type and dependency suppression), and correlation rules that tell a clear story (e.g. “port scan from preview”, “config → network”).

---

## 7. Summary for Scanner Updates

- **Done in codebase:** exec FP fix, path_type, namespace URL exclusion, OAuth tightening, dependency innerHTML suppression, dependency CVE pipeline (OSV).
- **To add (from this review):**  
  - Correlation: localhost_access + webview/preview path → “port scan from preview”.  
  - Heuristic: webview_risk in app preview path + user-content indicator → preview_xss or severity boost.  
  - Optional: unauthenticated server pattern, webhook+file pattern, command: in HTML, settings/workspace + network correlation.

Use this document as the **Bablu-backed list of missing patterns and enhancements** for the detection library; implement in order above or by priority.
