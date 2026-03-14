"""
VSCode Extension Static Analyzer - Four-Layer Security Assessment

Implements security analysis based on:
  Layer 1: Metadata & Publisher Analysis
  Layer 2: Supply Chain Security (dependency scanning)
  Layer 3: Deep Code Analysis & Behavioral Profiling
  Layer 4: Risk Scoring & Classification

Reference: "Automated Security Framework for VS Code Extensions"
           (NHSJS 2025 - Risk Profiling, Policy Generation, Runtime Sandboxing)
"""

import re
import os
import json
import math
import hashlib
import time
from pathlib import Path
from collections import defaultdict


# #region agent log
def _agent_debug_log(hypothesis_id, location, message, data=None, run_id="pre-fix"):
    """
    Lightweight debug logger for performance investigation.
    Writes NDJSON lines to .cursor/debug.log as required by debug mode.
    """
    try:
        payload = {
            "id": f"log_{int(time.time() * 1000)}",
            "timestamp": int(time.time() * 1000),
            "location": location,
            "message": message,
            "data": data or {},
            "runId": run_id,
            "hypothesisId": hypothesis_id,
        }
        log_dir = Path(__file__).resolve().parents[1] / ".cursor"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "debug.log"
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        # Debug logging must never break analysis
        pass
# #endregion


class VSCodeStaticAnalyzer:
    """Performs four-layer static security analysis on VSCode extensions"""

    # ──────────────────────────────────────────────────────────────────────
    # Layer 1: Metadata risk thresholds (from paper)
    # ──────────────────────────────────────────────────────────────────────
    LOW_ADOPTION_THRESHOLD = 500
    STALE_UPDATE_DAYS = 730  # 2 years
    FEW_RATINGS_THRESHOLD = 5

    # Broad/risky activation events
    # High-risk activation events (Phase 2 triage: startup = bigger attack surface)
    RISKY_ACTIVATION_EVENTS = {
        '*': 'Runs at VS Code startup - biggest attack surface',
        'onStartupFinished': 'Runs every launch - immediate execution',
        'workspaceContains': 'Auto-runs when repo opened - can trigger on any workspace',
        'onCommand': 'Runs when command triggered - user/shortcut driven',
        'onDebug': 'Access to debug session - can inspect/inject',
        'onUri': 'Activates on custom URI scheme (can be triggered externally)',
    }

    # Known vulnerable VS Code extensions (from public CVEs / research)
    # These are treated similarly to known malicious npm packages: if present,
    # they immediately raise the baseline risk for the extension under scan.
    # risk_context: 'localhost_exposure' = dev-server CORS issue, not malware. Report narrative should be calibrated.
    KNOWN_VULNERABLE_EXTENSIONS = {
        # Live Server - CVE-2025-65717 (localhost exposure, not malicious extension behaviour)
        'ritwickdey.LiveServer': {
            'cve': 'CVE-2025-65717',
            'severity': 'critical',
            'risk_context': 'localhost_exposure',
            'description': (
                'Live Server vulnerability allows remote webpages to crawl and exfiltrate '
                'files from the developer\'s localhost dev server (no CORS protection on '
                'http://localhost:5500). Requires user to browse a malicious site while server runs.'
            ),
            'mitigation_note': 'Update extension; avoid browsing untrusted sites while running local servers.',
            'reference': 'https://www.ox.security/blog/cve-2025-65717-live-server-vscode-vulnerability/'
        },
        # Code Runner - CVE-2025-65715
        # Unsafe spawn(..., { shell: true }) with executor command taken from settings.json
        'formulahendry.code-runner': {
            'cve': 'CVE-2025-65715',
            'severity': 'critical',
            'description': (
                'Code Runner vulnerability: executor commands from settings.json are passed '
                'directly into child_process.spawn(..., { shell: true }) allowing arbitrary '
                'code execution when settings are manipulated.'
            ),
            'reference': 'https://www.ox.security/blog/cve-2025-65715-code-runner-vscode-rce/'
        },
        # Markdown Preview Enhanced - CVE-2025-65716
        # Arbitrary JS execution in markdown preview iframe with localhost access
        'shd101wyy.markdown-preview-enhanced': {
            'cve': 'CVE-2025-65716',
            'severity': 'critical',
            'risk_context': 'localhost_exposure',
            'description': (
                'Markdown Preview Enhanced vulnerability allows crafted Markdown to execute '
                'arbitrary JavaScript in the preview iframe, enabling localhost port '
                'scanning and potential data exfiltration.'
            ),
            'mitigation_note': (
                'Vulnerability requires opening a crafted Markdown file. '
                'Risk is limited to dev environments. Update to latest version.'
            ),
            'reference': 'https://www.ox.security/blog/cve-2025-65716-markdown-preview-enhanced-vscode-vulnerability/'
        },
        # Arduino extension - CVE-2024-43488
        # Remote, unauthenticated RCE due to missing authentication on critical functionality
        'vsciot-vscode.vscode-arduino': {
            'cve': 'CVE-2024-43488',
            'severity': 'critical',
            'description': (
                'VS Code Arduino extension RCE: missing authentication on critical '
                'functionality exposes a remotely exploitable command execution surface.'
            ),
            'reference': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43488'
        },
        # Microsoft Live Preview / Live Server-style local file exfil (Trail of Bits research)
        # XSS / webview escape -> file+.vscode-resource.vscode-cdn.net exfiltration
        'ms-vscode.live-server': {
            'cve': None,
            'severity': 'critical',
            'description': (
                'Live Preview / Live Server-style extension with history of webview escape '
                'and filesystem exfiltration: treat as high-risk until fully audited.'
            ),
            'reference': 'https://blog.trailofbits.com/2023/02/21/vscode-extension-escape-vulnerability/'
        },
        'MS-SarifVSCode.sarif-viewer': {
            'cve': None,
            'severity': 'critical',
            'description': (
                'SARIF Viewer extension was previously affected by file exfiltration issues '
                'via VS Code webview escape techniques; treat as high-risk if unpatched.'
            ),
            'reference': 'https://blog.trailofbits.com/2023/02/21/vscode-extension-escape-vulnerability/'
        },
    }

    # Sensitive contribution points (from paper)
    # High-risk contributes (Phase 2: terminal/tasks/debug/webview/filesystem)
    SENSITIVE_CONTRIBUTIONS = {
        'terminal': 'Can create and control integrated terminals (command execution risk)',
        'terminalProfiles': 'Can define custom terminal profiles',
        'taskDefinitions': 'Can define tasks that run shell commands',
        'tasks': 'Task execution - shell/script execution',
        'debuggers': 'Can inspect running processes and variables (run arbitrary programs)',
        'authentication': 'Token/credential access as auth provider',
        'customEditors': 'Webview-based editors - XSS/phishing surface',
        'viewsContainers': 'Webview views - remote HTML/JS possible',
        'fileSystemProvider': 'Read/write workspace and virtual filesystem',
        'walkthroughs': 'Can present guided flows to users',
    }

    # ──────────────────────────────────────────────────────────────────────
    # Layer 2: Supply chain - known vulnerable/malicious packages
    # ──────────────────────────────────────────────────────────────────────
    SUSPICIOUS_PACKAGES = {
        # Known typosquat / malicious npm packages
        'event-stream': 'Known supply chain attack (flatmap-stream incident)',
        'ua-parser-js': 'Compromised in Oct 2021 (crypto-miner injected)',
        'coa': 'Compromised in Nov 2021',
        'rc': 'Compromised in Nov 2021',
        'colors': 'Sabotaged by maintainer (infinite loop)',
        'faker': 'Sabotaged by maintainer',
        'node-ipc': 'Protestware - wiped files on Russian/Belarusian IPs',
    }

    # ──────────────────────────────────────────────────────────────────────
    # Layer 3: Deep Code Analysis patterns
    # ──────────────────────────────────────────────────────────────────────

    # Sensitive Node.js modules (from paper Table 1)
    SENSITIVE_MODULES = {
        'file_access': ['fs', 'fs/promises', 'path', 'stream'],
        'network': ['http', 'https', 'http2', 'net', 'dgram', 'tls', 'dns', 'url',
                     'axios', 'got', 'node-fetch', 'superagent', 'request', 'ws'],
        'process_execution': ['child_process', 'process'],
        'os_info': ['os'],
        'crypto': ['crypto'],
        'vm': ['vm'],
    }

    # Command injection patterns (require child_process context to avoid FPs on regex .exec())
    COMMAND_INJECTION_PATTERNS = [
        {
            'name': 'child_process.exec with dynamic args',
            'pattern': re.compile(
                r'child_process\s*\.\s*exec\s*\(\s*(?:`[^`]*\$\{|[a-zA-Z_]\w*(?:\s*\+|\[))',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Command execution with dynamic/interpolated arguments - command injection risk',
            'category': 'command_injection'
        },
        {
            'name': 'child_process.exec with shell=true',
            'pattern': re.compile(
                r'(?:spawn|execFile|fork)\s*\([^)]*shell\s*:\s*true',
                re.MULTILINE | re.DOTALL
            ),
            'severity': 'high',
            'description': 'Process spawning with shell=true allows shell metacharacter injection',
            'category': 'command_injection'
        },
        {
            'name': 'exec/spawn with user input',
            'pattern': re.compile(
                r'(?:exec|spawn|execFile)\s*\(\s*(?:input|userInput|command|cmd|args|param)',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Process execution with user-controlled input',
            'category': 'command_injection'
        },
        {
            'name': 'promisify(exec) async shell capability',
            'pattern': re.compile(
                r'promisify\s*\(\s*(?:exec|execFile)\s*\)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Promisified child_process execution - async shell command capability',
            'category': 'command_injection'
        },
        {
            'name': 'Shell command built via helper function',
            'pattern': re.compile(
                r'(?:exec|execAsync|execSync|execFile)\s*\(\s*(?:build|create|make|get|construct|format|compose)\w*\s*\(',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Shell command constructed via helper function - review function for user input injection',
            'category': 'command_injection'
        },
        {
            'name': 'Variable-built command passed to exec',
            'pattern': re.compile(
                r'(?:const|let|var)\s+(?:cmd|command|shellCmd)\s*=\s*[^;]+;'
                r'[\s\S]{0,300}?'
                r'(?:exec|execAsync|spawn|execFile)\s*\(\s*(?:cmd|command|shellCmd)\b',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Command built into variable then passed to shell execution - review command construction for injection',
            'category': 'command_injection'
        },
    ]

    # Unsafe code execution patterns (from paper)
    UNSAFE_CODE_PATTERNS = [
        {
            'name': 'eval() usage',
            'pattern': re.compile(r'(?<!\.)(?<!\.prototype\.)(?<!\w)\beval\s*\(', re.MULTILINE),
            'severity': 'high',
            'description': 'Dynamic code execution via eval()',
            'category': 'code_execution'
        },
        {
            'name': 'new Function() constructor',
            'pattern': re.compile(r'new\s+Function\s*\(', re.MULTILINE),
            'severity': 'high',
            'description': 'Dynamic code execution via Function constructor',
            'category': 'code_execution'
        },
        {
            'name': 'vm.runInContext / vm.runInNewContext',
            'pattern': re.compile(r'vm\s*\.\s*(?:runIn(?:New)?Context|createContext|Script)', re.MULTILINE),
            'severity': 'high',
            'description': 'VM module code execution - can escape sandbox',
            'category': 'code_execution'
        },
        {
            'name': 'setTimeout/setInterval with string',
            'pattern': re.compile(
                r'(?:setTimeout|setInterval)\s*\(\s*["\']',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'setTimeout/setInterval with string argument acts as eval()',
            'category': 'code_execution'
        },
        {
            'name': 'require() with dynamic path',
            'pattern': re.compile(
                r'require\s*\(\s*(?:[a-zA-Z_]\w*(?:\s*\+|\[)|`[^`]*\$\{)',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Dynamic require() can load arbitrary modules',
            'category': 'code_execution'
        },
    ]

    # Filesystem access patterns - sensitive paths (from paper)
    SENSITIVE_PATH_PATTERNS = [
        {
            'name': 'SSH key access',
            'pattern': re.compile(r'["\'](?:~|\$HOME|process\.env\.HOME)[/\\]?\.ssh[/\\]', re.MULTILINE),
            'severity': 'critical',
            'description': 'Accesses SSH private keys (~/.ssh/)',
            'category': 'credential_theft'
        },
        {
            'name': 'AWS credential access',
            'pattern': re.compile(r'["\'](?:~|\$HOME|process\.env\.HOME)[/\\]?\.aws[/\\]', re.MULTILINE),
            'severity': 'critical',
            'description': 'Accesses AWS credentials (~/.aws/)',
            'category': 'credential_theft'
        },
        {
            'name': '.env file access',
            'pattern': re.compile(r'(?:readFile|readFileSync)\s*\([^)]*\.env["\']', re.MULTILINE),
            'severity': 'critical',
            'description': 'Reads .env file containing secrets',
            'category': 'credential_theft'
        },
        {
            'name': '.git/config access',
            'pattern': re.compile(r'["\'](?:.*?)\.git[/\\]config["\']', re.MULTILINE),
            'severity': 'high',
            'description': 'Accesses .git/config (may contain tokens)',
            'category': 'credential_theft'
        },
        {
            'name': 'Browser profile access',
            'pattern': re.compile(
                r'["\'].*?(?:AppData|Application Support|\.config)[/\\]'
                r'(?:Google[/\\]Chrome|Mozilla[/\\]Firefox|BraveSoftware|Microsoft[/\\]Edge)',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Accesses browser profile data (passwords, cookies, history)',
            'category': 'credential_theft'
        },
        {
            'name': 'VS Code settings/secrets access',
            'pattern': re.compile(
                r'["\'].*?(?:\.vscode|Code[/\\]User)[/\\](?:settings\.json|keybindings|secrets)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Accesses VS Code user settings or secrets storage',
            'category': 'settings_theft'
        },
        {
            'name': 'Known password/token file access',
            'pattern': re.compile(
                r'["\'].*?(?:\.npmrc|\.pypirc|\.docker[/\\]config\.json|\.kube[/\\]config|\.netrc)',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Accesses files known to contain authentication tokens',
            'category': 'credential_theft'
        },
        {
            'name': 'Home directory enumeration',
            'pattern': re.compile(
                r'(?:readdirSync|readdir)\s*\(\s*(?:os\.homedir|process\.env\.HOME|process\.env\.USERPROFILE)',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Enumerates home directory contents',
            'category': 'reconnaissance'
        },
    ]

    # Network exfiltration patterns
    NETWORK_PATTERNS = [
        {
            'name': 'HTTP POST with sensitive data',
            'pattern': re.compile(
                r'(?:https?\.request|fetch|axios\.post|got\.post)\s*\('
                r'[^)]*(?:method\s*:\s*["\']POST|\.post\s*\()',
                re.MULTILINE | re.DOTALL
            ),
            'severity': 'medium',
            'description': 'Sends data via HTTP POST request',
            'category': 'network_exfil'
        },
        {
            'name': 'WebSocket connection',
            'pattern': re.compile(r'new\s+WebSocket\s*\(', re.MULTILINE),
            'severity': 'medium',
            'description': 'Opens WebSocket connection (persistent data channel)',
            'category': 'network_exfil'
        },
        {
            'name': 'DNS exfiltration pattern',
            'pattern': re.compile(r'dns\s*\.\s*(?:resolve|lookup)\s*\(', re.MULTILINE),
            'severity': 'medium',
            'description': 'DNS resolution - potential DNS tunneling/exfiltration',
            'category': 'network_exfil'
        },
        {
            'name': 'Encoded data in URL',
            'pattern': re.compile(
                r'(?:encodeURIComponent|btoa|Buffer\.from)\s*\([^)]*\)\s*[+`]?\s*'
                r'(?:https?|wss?)\s*:',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Encodes data and embeds in URL (data exfiltration pattern)',
            'category': 'network_exfil'
        },
        {
            'name': 'IP-based connection',
            'pattern': re.compile(
                r'["\']https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Connects to raw IP address (C2 indicator)',
            'category': 'network_exfil'
        },
    ]

    # VSCode API abuse patterns
    VSCODE_API_ABUSE_PATTERNS = [
        {
            'name': 'Terminal creation',
            'pattern': re.compile(
                r'vscode\s*\.\s*window\s*\.\s*createTerminal\s*\(',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Creates integrated terminal (can execute arbitrary commands)',
            'category': 'terminal_hijack'
        },
        {
            'name': 'Terminal sendText (command execution)',
            'pattern': re.compile(
                r'\.sendText\s*\(\s*(?:[a-zA-Z_]\w*|`[^`]*\$\{)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Sends commands to terminal with dynamic content',
            'category': 'terminal_hijack'
        },
        {
            'name': 'Document content reading',
            'pattern': re.compile(
                r'(?:document\.getText|editor\.document\.getText)\s*\(',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Reads open document content (common but trackable)',
            'category': 'data_access'
        },
        {
            'name': 'Workspace file access',
            'pattern': re.compile(
                r'vscode\s*\.\s*workspace\s*\.\s*(?:findFiles|openTextDocument|fs\s*\.\s*readFile)',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Accesses workspace files',
            'category': 'data_access'
        },
        {
            'name': 'Real-time document change listener',
            'pattern': re.compile(
                r'(?:onDidChangeTextDocument|onDidChangeActiveTextEditor)\s*\(\s*(?:async\s*)?\(?',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Monitors text document changes in real time - common in AI assistants, review data destinations',
            'category': 'document_monitoring'
        },
        {
            'name': 'Extension access (hijacking)',
            'pattern': re.compile(
                r'vscode\s*\.\s*extensions\s*\.\s*getExtension\s*\(',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Accesses other installed extensions (potential extension hijacking)',
            'category': 'extension_hijack'
        },
        {
            'name': 'Clipboard access',
            'pattern': re.compile(
                r'vscode\s*\.\s*env\s*\.\s*clipboard\s*\.\s*(?:readText|writeText)',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Accesses clipboard (read/write)',
            'category': 'data_access'
        },
        {
            'name': 'Secret storage access',
            'pattern': re.compile(
                r'(?:secretStorage|secrets)\s*\.\s*(?:get|store|delete)',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Accesses VS Code secret storage API',
            'category': 'credential_theft'
        },
        {
            'name': 'Configuration modification',
            'pattern': re.compile(
                r'(?:workspace|vscode)\s*\.\s*(?:getConfiguration|configuration)\s*\([^)]*\)\s*\.\s*update',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Modifies VS Code settings programmatically',
            'category': 'settings_manipulation'
        },
        {
            'name': 'Code Runner executorMap settings modification',
            'pattern': re.compile(
                r'getConfiguration\s*\(\s*["\']code-runner["\']\s*\)[^;]*\.\s*update\s*\(\s*["\']executorMap["\']',
                re.MULTILINE | re.DOTALL
            ),
            'severity': 'high',
            'description': 'Updates code-runner.executorMap in settings - can weaponize executors for RCE (CVE-2025-65715 pattern)',
            'category': 'settings_manipulation'
        },
        {
            'name': 'command: URI string usage',
            'pattern': re.compile(
                r'["\']command:[^"\']+["\']',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Uses VS Code command: URI scheme - can trigger arbitrary commands when combined with trusted content or webviews/notebooks',
            'category': 'command_uri'
        },
        {
            'name': 'Webview with scripts enabled',
            'pattern': re.compile(
                r'enableScripts\s*:\s*true',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Webview with JavaScript enabled (XSS vector if loading external content)',
            'category': 'webview_risk'
        },
        {
            'name': 'Webview innerHTML assignment',
            'pattern': re.compile(
                r'\.innerHTML\s*=\s*(?![\s]*["\']<)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Direct innerHTML assignment with dynamic content (XSS vulnerability)',
            'category': 'webview_risk'
        },
    ]

    # Obfuscation / evasion patterns
    OBFUSCATION_PATTERNS = [
        {
            'name': 'Hex-encoded strings',
            'pattern': re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}'),
            'severity': 'high',
            'description': 'Long hex-encoded string sequences (code obfuscation)',
            'category': 'obfuscation'
        },
        {
            'name': 'Unicode escape sequences',
            'pattern': re.compile(r'\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}'),
            'severity': 'high',
            'description': 'Long unicode escape sequences (string obfuscation)',
            'category': 'obfuscation'
        },
        {
            'name': 'Base64 encoded blocks',
            'pattern': re.compile(
                r'["\'][A-Za-z0-9+/]{50,}={0,2}["\']',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Large base64-encoded string (hidden payload)',
            'category': 'obfuscation',
            '_post_validate': 'base64_not_hex'
        },
        {
            'name': 'String concatenation obfuscation',
            'pattern': re.compile(
                r'(?:["\'][a-zA-Z]{1,3}["\'])\s*\+\s*(?:["\'][a-zA-Z]{1,3}["\'])\s*\+'
                r'\s*(?:["\'][a-zA-Z]{1,3}["\'])\s*\+\s*(?:["\'][a-zA-Z]{1,3}["\'])',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'String built from small concatenated pieces (anti-detection)',
            'category': 'obfuscation'
        },
        {
            'name': 'Control flow flattening',
            'pattern': re.compile(
                r'switch\s*\(\s*\w+\s*\[\s*\w+\s*\+\+\s*\]\s*\)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Control flow flattening pattern (advanced obfuscation)',
            'category': 'obfuscation'
        },
    ]

    # Weak cryptography patterns (from paper)
    WEAK_CRYPTO_PATTERNS = [
        {
            'name': 'MD5 usage',
            'pattern': re.compile(r'createHash\s*\(\s*["\']md5["\']', re.MULTILINE),
            'severity': 'medium',
            'description': 'MD5 hash usage (cryptographically broken)',
            'category': 'weak_crypto'
        },
        {
            'name': 'SHA1 usage',
            'pattern': re.compile(r'createHash\s*\(\s*["\']sha1["\']', re.MULTILINE),
            'severity': 'low',
            'description': 'SHA1 hash usage (deprecated for security)',
            'category': 'weak_crypto'
        },
        {
            'name': 'DES/RC4 usage',
            'pattern': re.compile(r'createCipher(?:iv)?\s*\(\s*["\'](?:des|rc4)', re.MULTILINE | re.IGNORECASE),
            'severity': 'high',
            'description': 'DES/RC4 cipher usage (broken encryption)',
            'category': 'weak_crypto'
        },
        {
            'name': 'Hardcoded IV/key',
            'pattern': re.compile(
                r'(?:iv|key|secret|password)\s*=\s*["\'][A-Fa-f0-9]{16,}["\']',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Hardcoded cryptographic key or IV',
            'category': 'weak_crypto'
        },
    ]

    # Prototype pollution patterns (from paper)
    PROTOTYPE_POLLUTION_PATTERNS = [
        {
            'name': '__proto__ assignment',
            'pattern': re.compile(r'__proto__\s*[=\[]', re.MULTILINE),
            'severity': 'high',
            'description': 'Direct __proto__ manipulation (prototype pollution)',
            'category': 'prototype_pollution'
        },
        {
            'name': 'Unsafe Object.assign with user input',
            'pattern': re.compile(
                r'Object\.assign\s*\(\s*(?:{}|Object\.create\(null\)|target|this)',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Object.assign with potentially untrusted source',
            'category': 'prototype_pollution'
        },
        {
            'name': 'constructor.prototype access',
            'pattern': re.compile(r'constructor\s*\.\s*prototype', re.MULTILINE),
            'severity': 'medium',
            'description': 'Accessing constructor.prototype (potential prototype pollution)',
            'category': 'prototype_pollution'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # Workspace harvesting patterns (ChatMoss-validated)
    # ──────────────────────────────────────────────────────────────────────
    WORKSPACE_HARVESTING_PATTERNS = [
        {
            'name': 'Recursive directory reading',
            'pattern': re.compile(
                r'(?:fs\s*\.\s*readdirSync|fs\s*\.\s*readdir)\s*\(',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Reads directory contents - suspicious when combined with file reading and network',
            'category': 'workspace_harvesting'
        },
        {
            'name': 'Bulk file reading with variable path',
            'pattern': re.compile(
                r'(?:fs\s*\.\s*readFileSync|fs\s*\.\s*readFile)\s*\(\s*(?:[a-zA-Z_]\w*)',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Reads file content using variable path - bulk file harvesting indicator',
            'category': 'workspace_harvesting'
        },
        {
            'name': 'Workspace folder enumeration',
            'pattern': re.compile(
                r'vscode\s*\.\s*workspace\s*\.\s*workspaceFolders',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Accesses workspace root folder path',
            'category': 'workspace_harvesting'
        },
        {
            'name': 'File content to base64 conversion',
            'pattern': re.compile(
                r'Buffer\s*\.\s*from\s*\([^)]*\)\s*\.\s*toString\s*\(\s*["\']base64["\']',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Converts file content to base64 - data exfiltration preparation (ChatMoss pattern)',
            'category': 'workspace_harvesting'
        },
        {
            'name': 'VSCode filesystem bulk read',
            'pattern': re.compile(
                r'vscode\s*\.\s*workspace\s*\.\s*fs\s*\.\s*readFile',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Reads files via VSCode workspace filesystem API',
            'category': 'workspace_harvesting'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # Base64 / compression exfiltration patterns
    # ──────────────────────────────────────────────────────────────────────
    BASE64_EXFIL_PATTERNS = [
        {
            'name': 'Base64 encoding of content variable',
            'pattern': re.compile(
                r'(?:btoa|Buffer\.from)\s*\(\s*(?:[a-zA-Z_]\w*(?:content|file|data|text|body|code)\w*)',
                re.MULTILINE | re.IGNORECASE
            ),
            'severity': 'high',
            'description': 'Base64 encodes content/file data - exfiltration preparation',
            'category': 'base64_exfil'
        },
        {
            'name': 'Base64 data sent via webview postMessage',
            'pattern': re.compile(
                r'(?:postMessage|webview\s*\.\s*postMessage)\s*\(\s*(?:JSON\.stringify\s*\()?\s*\{[^}]*base64',
                re.MULTILINE | re.DOTALL
            ),
            'severity': 'high',
            'description': 'Base64-encoded data sent via webview message - data exfiltration channel',
            'category': 'base64_exfil'
        },
        {
            'name': 'Zlib/gzip compression before transmission',
            'pattern': re.compile(
                r'(?:zlib\s*\.\s*(?:gzip|deflate|createGzip|createDeflate)|pako\s*\.\s*(?:gzip|deflate))\s*\(',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Data compression before network transmission - exfiltration obfuscation',
            'category': 'base64_exfil'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # Document monitoring patterns (ChatMoss-validated)
    # ──────────────────────────────────────────────────────────────────────
    DOCUMENT_MONITORING_PATTERNS = [
        {
            'name': 'Active editor fileName access',
            'pattern': re.compile(
                r'(?:editor|activeEditor)\s*\.?\s*document\s*\.\s*(?:fileName|uri)',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Accesses the filename/path of the active document',
            'category': 'document_monitoring'
        },
        {
            'name': 'File content read on editor change event',
            'pattern': re.compile(
                r'onDidChange(?:ActiveTextEditor|TextDocument)\s*\([^)]*\)\s*(?:=>|function)',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Registers handler for editor/document change events',
            'category': 'document_monitoring'
        },
        {
            'name': 'Long-delay setTimeout/setInterval (>10 seconds)',
            'pattern': re.compile(
                r'(?:setTimeout|setInterval)\s*\([^,]+,\s*(\d{5,})\)',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Delayed execution with long timeout (>10s) - deferred behavior evasion',
            'category': 'document_monitoring'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # Workspace activity monitoring patterns (privacy-relevant telemetry)
    # ──────────────────────────────────────────────────────────────────────
    WORKSPACE_ACTIVITY_PATTERNS = [
        {
            'name': 'File open monitoring (onDidOpenTextDocument)',
            'pattern': re.compile(
                r'onDidOpenTextDocument\s*\(',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Monitors when files are opened in the editor - workspace activity tracking',
            'category': 'workspace_activity_monitoring'
        },
        {
            'name': 'File save monitoring (onWillSaveTextDocument)',
            'pattern': re.compile(
                r'onWillSaveTextDocument\s*\(',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Monitors when files are about to be saved - workspace activity tracking',
            'category': 'workspace_activity_monitoring'
        },
        {
            'name': 'Workspace folder change monitoring',
            'pattern': re.compile(
                r'onDidChangeWorkspaceFolders\s*\(',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Monitors workspace folder additions/removals - workspace structure tracking',
            'category': 'workspace_activity_monitoring'
        },
        {
            'name': 'Document fileName/path collection',
            'pattern': re.compile(
                r'document\s*\.\s*fileName',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Collects file paths from open documents - local filesystem path collection',
            'category': 'workspace_activity_monitoring'
        },
        {
            'name': 'Workspace folder fsPath collection',
            'pattern': re.compile(
                r'(?:folder|workspace)\s*\.\s*uri\s*\.\s*fsPath',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Collects workspace folder filesystem paths - local path enumeration',
            'category': 'workspace_activity_monitoring'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # HTTP endpoint / remote infrastructure patterns
    # ──────────────────────────────────────────────────────────────────────
    SUSPICIOUS_TLDS = {'.cn', '.ru', '.tk', '.ml', '.ga', '.cf', '.gq',
                       '.top', '.buzz', '.xyz', '.pw', '.cc', '.ws', '.su', '.to'}

    # Substrings that indicate XML/HTML namespace URLs (excluded from Plaintext HTTP FP)
    HTTP_NAMESPACE_URL_INDICATORS = (
        'w3.org', 'schemas.', 'xmlns', '1999/xhtml', '2000/svg',
        'Math/MathML', 'XML/1998', '1999/xlink',
    )

    HTTP_ENDPOINT_PATTERNS = [
        {
            'name': 'Plaintext HTTP endpoint (not HTTPS)',
            'pattern': re.compile(
                r'["\']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9._-]+',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Plaintext HTTP URL (not HTTPS) - data sent unencrypted',
            'category': 'insecure_endpoint'
        },
        {
            'name': 'Suspicious TLD in hardcoded domain',
            'pattern': re.compile(
                r'["\']https?://[a-zA-Z0-9._-]+\.(?:cn|ru|tk|ml|ga|cf|gq|top|buzz|xyz|pw|cc|ws|su|to)\b',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Hardcoded domain with suspicious TLD - untrusted remote endpoint',
            'category': 'insecure_endpoint'
        },
        {
            'name': 'Axios with Authorization header',
            'pattern': re.compile(
                r'axios\w*\s*[\.(][^;]*(?:Authorization|Bearer|X-Auth)',
                re.MULTILINE | re.DOTALL
            ),
            'severity': 'high',
            'description': 'Axios sends data with authorization headers - authenticated remote communication',
            'category': 'insecure_endpoint'
        },
        {
            'name': 'URL from extension configuration',
            'pattern': re.compile(
                r'(?:getConfiguration|configuration\s*\.\s*get)\s*\([^)]*\)[^;]*(?:url|Url|URL|endpoint|server)',
                re.MULTILINE | re.DOTALL
            ),
            'severity': 'medium',
            'description': 'URL constructed from extension configuration - configurable remote endpoint',
            'category': 'insecure_endpoint'
        },
        {
            'name': 'Localhost HTTP access from extension code',
            'pattern': re.compile(
                r'["\']https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0):?\d*',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Accesses localhost HTTP services from extension code - review for port scan or local file exfiltration behavior',
            'category': 'localhost_access'
        },
        {
            'name': 'HTTP client library import',
            'pattern': re.compile(
                r'(?:require|import)\s*\(?\s*["\'](?:axios|got|node-fetch|superagent|request)["\']',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'HTTP client library imported - enables outbound network communication',
            'category': 'insecure_endpoint'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # Telemetry abuse / analytics injection patterns
    # ──────────────────────────────────────────────────────────────────────
    TELEMETRY_ABUSE_PATTERNS = [
        {
            'name': 'Chinese analytics SDK injection',
            'pattern': re.compile(
                r'(?:zhuge|growingio|talkingdata|baidu\s*analytics|hm\.baidu|umeng|cnzz|51\.la)',
                re.MULTILINE | re.IGNORECASE
            ),
            'severity': 'high',
            'description': 'Chinese analytics/fingerprinting SDK embedded - user tracking',
            'category': 'telemetry_abuse'
        },
        {
            'name': 'User/device fingerprinting',
            'pattern': re.compile(
                r'(?:navigator\s*\.\s*(?:userAgent|language|platform|hardwareConcurrency|deviceMemory)|'
                r'screen\s*\.\s*(?:width|height|colorDepth|pixelDepth))',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Browser/device fingerprinting APIs used',
            'category': 'telemetry_abuse'
        },
        {
            'name': 'Machine ID / hostname collection',
            'pattern': re.compile(
                r'(?:os\s*\.\s*hostname\s*\(\)|os\s*\.\s*userInfo\s*\(\)|'
                r'vscode\s*\.\s*env\s*\.\s*(?:machineId|sessionId|appHost))',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Collects machine identity information (host fingerprinting)',
            'category': 'telemetry_abuse'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # Anti-evasion: VSCode API abuse (auth theft, task exec, browser exfil)
    # ──────────────────────────────────────────────────────────────────────
    VSCODE_API_EVASION_PATTERNS = [
        {
            'name': 'OAuth token theft via authentication.getSession',
            'pattern': re.compile(
                r'(?:vscode\s*\.\s*)?authentication\s*\.\s*getSession\s*\(',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Requests OAuth token via VSCode authentication API - can steal GitHub/Microsoft tokens',
            'category': 'auth_token_theft'
        },
        {
            'name': 'Browser-based exfiltration via env.openExternal',
            'pattern': re.compile(
                r'(?:vscode\s*\.\s*)?env\s*\.\s*openExternal\s*\(',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Opens URL in user browser - can exfiltrate data via URL parameters',
            'category': 'browser_exfil'
        },
        {
            'name': 'Command execution via ShellExecution/tasks API',
            'pattern': re.compile(
                r'(?:new\s+vscode\s*\.\s*ShellExecution|ShellExecution)\s*\(',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Creates shell command via Tasks API - executes commands without child_process',
            'category': 'command_injection'
        },
        {
            'name': 'Task execution via tasks.executeTask',
            'pattern': re.compile(
                r'(?:vscode\s*\.\s*)?tasks\s*\.\s*executeTask\s*\(',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Executes a VSCode task programmatically - can run shell commands',
            'category': 'command_injection'
        },
        {
            'name': 'Stealth terminal injection via sendSequence',
            'pattern': re.compile(
                r'terminal\.sendSequence|executeCommand\s*\(\s*["\']terminal\.sendSequence',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Injects keystrokes into active terminal without creating a new one',
            'category': 'terminal_hijack'
        },
        {
            'name': 'Task provider registration (shell execution)',
            'pattern': re.compile(
                r'(?:vscode\s*\.\s*)?tasks\s*\.\s*registerTaskProvider\s*\(',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Registers a task provider that can supply shell execution tasks',
            'category': 'command_injection'
        },
        {
            'name': 'Persistent state storage (globalState)',
            'pattern': re.compile(
                r'(?:context|ctx)\s*\.\s*globalState\s*\.\s*(?:update|get)\s*\(',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Uses globalState for persistent cross-session storage - can persist C2 config',
            'category': 'persistence'
        },
        {
            'name': 'Workspace state persistence',
            'pattern': re.compile(
                r'(?:context|ctx)\s*\.\s*workspaceState\s*\.\s*(?:update|get)\s*\(',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Uses workspaceState for per-workspace persistent storage',
            'category': 'persistence'
        },
        {
            'name': 'Installed extensions enumeration',
            'pattern': re.compile(
                r'vscode\s*\.\s*extensions\s*\.\s*all\b',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Enumerates all installed extensions - reconnaissance for extension hijacking',
            'category': 'reconnaissance'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # Anti-evasion: Indirect code execution patterns
    # ──────────────────────────────────────────────────────────────────────
    INDIRECT_CODE_EXECUTION_PATTERNS = [
        {
            'name': 'Indirect eval via comma operator (0,eval)',
            'pattern': re.compile(
                r'\(\s*\d\s*,\s*eval\s*\)',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Indirect eval via comma operator bypasses direct eval detection',
            'category': 'code_execution'
        },
        {
            'name': 'Function() constructor without new keyword',
            'pattern': re.compile(
                r'(?<!\bnew\s)(?<!\bnew\s\s)\bFunction\s*\(\s*["\']',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Function() called without new - code execution bypass',
            'category': 'code_execution'
        },
        {
            'name': 'Constructor chain code execution',
            'pattern': re.compile(
                r'\[\s*\]\s*\.\s*constructor\s*\.\s*constructor\s*\(',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Array constructor chain ([].constructor.constructor) for code execution',
            'category': 'code_execution'
        },
        {
            'name': 'Reflect.construct / Reflect.apply for code execution',
            'pattern': re.compile(
                r'Reflect\s*\.\s*(?:construct|apply)\s*\(\s*(?:Function|eval)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Reflect API used to invoke Function/eval indirectly',
            'category': 'code_execution'
        },
        {
            'name': 'Dynamic import() for code loading',
            'pattern': re.compile(
                r'\bimport\s*\(\s*(?:[a-zA-Z_]\w*|`[^`]*\$\{|["\']data:)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Dynamic import() can load arbitrary code modules at runtime',
            'category': 'code_execution'
        },
        {
            'name': 'vm.compileFunction execution',
            'pattern': re.compile(
                r'vm\s*\.\s*compileFunction\s*\(',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'vm.compileFunction creates executable function from string',
            'category': 'code_execution'
        },
        {
            'name': 'Eval via bracket notation (globalThis/window/global)',
            'pattern': re.compile(
                r'(?:globalThis|window|global|this|g)\s*\[\s*["\']ev',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Eval accessed via bracket notation to evade static detection',
            'category': 'code_execution'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # Anti-evasion: Stream/async file access and path.join credential paths
    # ──────────────────────────────────────────────────────────────────────
    EVASION_FILE_ACCESS_PATTERNS = [
        {
            'name': 'File reading via createReadStream',
            'pattern': re.compile(
                r'(?:fs\s*\.\s*)?createReadStream\s*\(',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Reads files via stream - bypasses readFile/readFileSync detection',
            'category': 'workspace_harvesting'
        },
        {
            'name': 'Async directory listing via fs.promises / fs/promises',
            'pattern': re.compile(
                r'(?:fsp|fsPromises|fs\s*\.\s*promises)\s*\.\s*readdir\s*\(',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Async directory listing bypasses fs.readdirSync detection',
            'category': 'workspace_harvesting'
        },
        {
            'name': 'Credential path via path.join with homedir',
            'pattern': re.compile(
                r'path\s*\.\s*join\s*\(\s*(?:home|homedir|os\s*\.\s*homedir\s*\(\)|userHome)\s*'
                r'[,)][^)]*(?:\.ssh|\.aws|\.kube|\.docker|\.gnupg|\.config[/\\]gh|\.azure|\.npmrc|\.netrc)',
                re.MULTILINE | re.DOTALL
            ),
            'severity': 'high',
            'description': 'Sensitive credential path built via path.join - evades string literal detection',
            'category': 'credential_theft'
        },
        {
            'name': 'fs/promises import (evasion module)',
            'pattern': re.compile(
                r'require\s*\(\s*["\']fs/promises["\']',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Imports fs/promises module - can bypass fs.readFile pattern matching',
            'category': 'workspace_harvesting'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # Anti-evasion: Network exfiltration via GET, raw TCP, webhooks
    # ──────────────────────────────────────────────────────────────────────
    EVASION_NETWORK_PATTERNS = [
        {
            'name': 'HTTPS GET-based data exfiltration',
            'pattern': re.compile(
                r'https\s*\.\s*get\s*\(\s*(?:`[^`]*\$\{|[a-zA-Z_]\w*\s*\+)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Data exfiltrated via HTTPS GET with dynamic URL (data in path/params)',
            'category': 'network_exfil'
        },
        {
            'name': 'Raw TCP socket connection (net.Socket)',
            'pattern': re.compile(
                r'(?:new\s+)?(?:net\s*\.\s*)?Socket\s*\(\s*\)\s*[;.]|'
                r'socket\s*\.\s*connect\s*\(\s*\d',
                re.MULTILINE | re.IGNORECASE
            ),
            'severity': 'high',
            'description': 'Raw TCP socket - can exfiltrate data without HTTP protocol detection',
            'category': 'network_exfil'
        },
        {
            'name': 'Discord webhook exfiltration',
            'pattern': re.compile(
                r'discord\.com/api/webhooks/',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Discord webhook URL - commonly used for malware C2/exfiltration',
            'category': 'network_exfil'
        },
        {
            'name': 'Telegram Bot API exfiltration',
            'pattern': re.compile(
                r'api\.telegram\.org/bot',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Telegram Bot API - commonly used for malware C2/exfiltration',
            'category': 'network_exfil'
        },
        {
            'name': 'Ngrok/Cloudflare tunnel C2 endpoint',
            'pattern': re.compile(
                r'["\']https?://[a-zA-Z0-9._-]+\.(?:ngrok\.io|ngrok-free\.app|trycloudflare\.com)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Ngrok/Cloudflare tunnel endpoint - disposable C2 infrastructure',
            'category': 'insecure_endpoint'
        },
        {
            'name': 'Pastebin/Gist C2 channel',
            'pattern': re.compile(
                r'(?:pastebin\.com/raw/|gist\.githubusercontent\.com/)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Pastebin/GitHub Gist URL for C2 instruction fetch',
            'category': 'network_exfil'
        },
        {
            'name': 'node: prefix module import',
            'pattern': re.compile(
                r'require\s*\(\s*["\']node:(?:child_process|fs|http|https|net|dgram)["\']',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Node.js module imported with node: prefix - may evade standard import detection',
            'category': 'evasion_technique'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # Anti-evasion: Obfuscation via charCode, array.join, hex decode
    # ──────────────────────────────────────────────────────────────────────
    EVASION_OBFUSCATION_PATTERNS = [
        {
            'name': 'String.fromCharCode array building',
            'pattern': re.compile(
                r'(?:String\s*\.\s*fromCharCode\s*\.\s*apply|'
                r'\.map\s*\(\s*(?:c\s*=>|function)\s*[^)]*String\s*\.\s*fromCharCode|'
                r'String\s*\.\s*fromCharCode\s*\(\s*\d+\s*(?:,\s*\d+\s*){3,})',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'String built from charCode array - string obfuscation technique',
            'category': 'obfuscation'
        },
        {
            'name': 'Array.join string assembly',
            'pattern': re.compile(
                r'\[\s*["\'][a-zA-Z_]{1,6}["\'](?:\s*,\s*["\'][a-zA-Z_]{1,6}["\']){2,}\s*\]\s*\.\s*join\s*\(',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'String assembled from array fragments via join() - evades concatenation detection',
            'category': 'obfuscation'
        },
        {
            'name': 'Buffer.from hex string decoding',
            'pattern': re.compile(
                r'Buffer\s*\.\s*from\s*\(\s*["\'][0-9a-fA-F]{10,}["\']\s*,\s*["\']hex["\']',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Hex-encoded string decoded at runtime - hides sensitive strings',
            'category': 'obfuscation'
        },
        {
            'name': 'Reduce-based string building',
            'pattern': re.compile(
                r'\.reduce\s*\(\s*(?:\(\s*\w+\s*,\s*\w+\s*\)\s*=>|function)[^)]*String\s*\.\s*fromCharCode',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'String built via reduce + fromCharCode - advanced obfuscation',
            'category': 'obfuscation'
        },
        {
            'name': 'XOR-based string decoding',
            'pattern': re.compile(
                r'\.map\s*\(\s*(?:\w+\s*=>|function)[^)]*charCodeAt[^)]*\^\s*(?:\w+|0x[0-9a-fA-F]+|\d+)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'XOR decoding of character codes - encryption-based obfuscation',
            'category': 'obfuscation'
        },
        {
            'name': 'Hex encoding for data exfiltration',
            'pattern': re.compile(
                r'Buffer\s*\.\s*from\s*\([^)]+\)\s*\.\s*toString\s*\(\s*["\']hex["\']',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Data encoded as hex string - exfiltration encoding alternative to base64',
            'category': 'base64_exfil'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # Anti-evasion: Hardware fingerprinting and env harvesting
    # ──────────────────────────────────────────────────────────────────────
    EVASION_FINGERPRINT_PATTERNS = [
        {
            'name': 'CPU hardware fingerprinting',
            'pattern': re.compile(
                r'os\s*\.\s*cpus\s*\(\s*\)',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Reads CPU model/cores/speed - unique hardware fingerprint',
            'category': 'telemetry_abuse'
        },
        {
            'name': 'Network interface / MAC address enumeration',
            'pattern': re.compile(
                r'os\s*\.\s*networkInterfaces\s*\(\s*\)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Enumerates network interfaces and MAC addresses - unique device identifier',
            'category': 'telemetry_abuse'
        },
        {
            'name': 'Memory fingerprinting',
            'pattern': re.compile(
                r'os\s*\.\s*(?:totalmem|freemem)\s*\(\s*\)',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Reads system memory info - hardware fingerprinting',
            'category': 'telemetry_abuse'
        },
        {
            'name': 'Process environment bulk harvesting',
            'pattern': re.compile(
                r'Object\s*\.\s*keys\s*\(\s*process\s*\.\s*env\s*\)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Enumerates all environment variable names - sensitive info harvesting',
            'category': 'telemetry_abuse'
        },
        {
            'name': 'Process memory/CPU usage collection',
            'pattern': re.compile(
                r'process\s*\.\s*(?:cpuUsage|memoryUsage)\s*\(\s*\)',
                re.MULTILINE
            ),
            'severity': 'low',
            'description': 'Collects process resource usage metrics',
            'category': 'telemetry_abuse'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # Anti-evasion: Module aliasing, destructuring, computed access
    # ──────────────────────────────────────────────────────────────────────
    MODULE_ALIASING_PATTERNS = [
        {
            'name': 'Destructured exec/spawn with rename',
            'pattern': re.compile(
                r'(?:const|let|var)\s*\{[^}]*exec\s*:\s*\w+[^}]*\}\s*=\s*require\s*\(\s*["\']child_process',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'child_process.exec destructured with rename - evades function name detection',
            'category': 'evasion_technique'
        },
        {
            'name': 'Computed property access on child_process',
            'pattern': re.compile(
                r'(?:cp|childProcess|proc|child)\s*\[\s*(?:["\'][^"\']+["\']|[a-zA-Z_]\w*)\s*\]\s*\(',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'child_process method called via bracket notation - evades dotted access detection',
            'category': 'evasion_technique'
        },
        {
            'name': 'Shell option via truthy coercion (shell: !0 or shell: 1)',
            'pattern': re.compile(
                r'shell\s*:\s*(?:!0|!false|1\b)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'shell:true passed as truthy coercion (!0, 1) to evade literal detection',
            'category': 'evasion_technique'
        },
        {
            'name': 'Indirect function call via .call/.apply/Reflect',
            'pattern': re.compile(
                r'(?:exec|spawn|execFile)\s*\.\s*(?:call|apply|bind)\s*\('
                r'|Reflect\s*\.\s*apply\s*\(\s*(?:\w+\s*\.\s*)?exec',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Process execution via .call/.apply/Reflect - evades direct invocation detection',
            'category': 'evasion_technique'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # V2 Capability Detection: Behavioral threat patterns
    # Works on both minified and readable code (no vscode. prefix required)
    # ──────────────────────────────────────────────────────────────────────
    CAPABILITY_PATTERNS = [
        # --- Clipboard surveillance ---
        {
            'name': 'Clipboard read access',
            'pattern': re.compile(
                r'clipboard\s*\.\s*readText\s*\(',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Reads clipboard content - potential data harvesting vector',
            'category': 'clipboard_access'
        },
        {
            'name': 'Clipboard write access',
            'pattern': re.compile(
                r'clipboard\s*\.\s*writeText\s*\(',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Writes to clipboard - can inject content (URLs, crypto addresses)',
            'category': 'clipboard_access'
        },
        # --- Hidden terminal / stealth execution ---
        {
            'name': 'Hidden terminal creation (hideFromUser)',
            'pattern': re.compile(
                r'hideFromUser\s*:\s*(?:true|!0|1\b)',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Creates terminal hidden from user - stealth command execution',
            'category': 'terminal_hijack'
        },
        {
            'name': 'Terminal creation (minification-safe)',
            'pattern': re.compile(
                r'createTerminal\s*\(\s*(?:\{|[a-zA-Z_]\w*)',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Creates VSCode terminal - can execute commands',
            'category': 'command_injection'
        },
        # --- Local server / tunneling ---
        {
            'name': 'Local HTTP server creation',
            'pattern': re.compile(
                r'(?:createServer|http\.Server|https\.Server)\s*\(',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Creates local HTTP server - potential remote control endpoint',
            'category': 'local_server'
        },
        {
            'name': 'Server listening on network interface',
            'pattern': re.compile(
                r'\.listen\s*\(\s*(?:this\.port|port|\d+)\s*,\s*["\']0\.0\.0\.0["\']',
                re.MULTILINE
            ),
            'severity': 'critical',
            'description': 'Server binds to all network interfaces (0.0.0.0) - exposed to network',
            'category': 'local_server'
        },
        {
            'name': 'Server port listening',
            'pattern': re.compile(
                r'\.listen\s*\(\s*(?:this\.port|port|\d{2,5})\s*(?:,|\))',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Opens a network port - potential remote access endpoint',
            'category': 'local_server'
        },
        # --- Identity harvesting ---
        {
            'name': 'GitHub user identity API call',
            'pattern': re.compile(
                r'api\.github\.com/user(?:/emails)?',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Fetches GitHub user identity/emails - account linking and tracking',
            'category': 'identity_harvesting'
        },
        {
            'name': 'OAuth token extraction from session',
            'pattern': re.compile(
                r'(?:accessToken|access_token|oauthToken|getToken\s*\(|Bearer\s+token|'
                r'auth\s*\.\s*token|session\s*\.\s*(?:accessToken|token)|credential\s*token)\b',
                re.MULTILINE
            ),
            'severity': 'medium',
            'description': 'Accesses authentication token - potential credential extraction',
            'category': 'identity_harvesting'
        },
        # --- Remote orchestration ---
        {
            'name': 'Generic data transport endpoint (/api/action or similar)',
            'pattern': re.compile(
                r'["\'/]api/(?:action|task|execute|run|command|agent)["\']',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Generic API endpoint for action/task execution - remote orchestration pattern',
            'category': 'remote_orchestration'
        },
        {
            'name': 'Remote access URL sharing',
            'pattern': re.compile(
                r'(?:Remote\s+access|Copy\s+URL|Share\s+(?:URL|link))',
                re.MULTILINE | re.IGNORECASE
            ),
            'severity': 'high',
            'description': 'Shares remote access URL - indicates tunneling/remote control capability',
            'category': 'remote_orchestration'
        },
        # --- child_process in minified code ---
        {
            'name': 'child_process require (minification-safe)',
            'pattern': re.compile(
                r'require\s*\(\s*["\']child_process["\']\s*\)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Imports child_process module - shell command execution capability',
            'category': 'command_injection'
        },
        {
            'name': 'Promisified exec (async shell execution)',
            'pattern': re.compile(
                r'promisify\s*\(\s*(?:exec|o)\s*\)',
                re.MULTILINE
            ),
            'severity': 'high',
            'description': 'Promisified exec - async shell command execution',
            'category': 'command_injection'
        },
    ]

    # ──────────────────────────────────────────────────────────────────────
    # Known library files (for false positive suppression)
    # ──────────────────────────────────────────────────────────────────────
    KNOWN_LIBRARY_FILES = {
        'vue.global.js', 'vue.esm-browser.js', 'vue.runtime.global.js',
        'vue.global.prod.js', 'vue.min.js',
        'react.development.js', 'react.production.min.js', 'react-dom.production.min.js',
        'highlight.min.js', 'highlight.js', 'prism.js', 'prism.min.js',
        'marked.min.js', 'markdown-it.min.js', 'markdown-it.js',
        'echarts.min.js', 'echarts.js',
        'lodash.min.js', 'lodash.js', 'underscore.min.js',
        'jquery.min.js', 'jquery.js',
        'codemirror.js', 'codemirror.min.js',
        'moment.min.js', 'dayjs.min.js',
        'katex.min.js', 'mathjax.js',
    }

    LIBRARY_SUPPRESSIBLE_CATEGORIES = {
        'obfuscation', 'prototype_pollution', 'webview_risk', 'code_execution',
    }

    # Popular packages for typosquatting detection
    POPULAR_PACKAGES = {
        'axios', 'lodash', 'express', 'react', 'vue', 'webpack',
        'typescript', 'moment', 'chalk', 'commander', 'debug',
        'uuid', 'dotenv', 'cors', 'body-parser', 'jsonwebtoken',
        'bcrypt', 'mongoose', 'sequelize', 'passport', 'socket.io',
        'ws', 'node-fetch', 'got', 'cheerio', 'puppeteer',
        'dayjs', 'date-fns', 'rxjs', 'ramda', 'immutable',
        'underscore', 'async', 'bluebird', 'co', 'glob',
        'minimist', 'yargs', 'inquirer', 'ora', 'semver',
    }
    # Legitimate short-names that often trigger typosquat (edit distance to popular); do not flag
    TYPOSQUAT_WHITELIST = {'opn', 'ips', 'open', 'path', 'util', 'rimraf', 'mkdirp', 'which'}

    def __init__(self):
        # Combine all pattern categories for scanning
        self.all_patterns = (
            self.COMMAND_INJECTION_PATTERNS +
            self.UNSAFE_CODE_PATTERNS +
            self.SENSITIVE_PATH_PATTERNS +
            self.NETWORK_PATTERNS +
            self.VSCODE_API_ABUSE_PATTERNS +
            self.OBFUSCATION_PATTERNS +
            self.WEAK_CRYPTO_PATTERNS +
            self.PROTOTYPE_POLLUTION_PATTERNS +
            self.WORKSPACE_HARVESTING_PATTERNS +
            self.BASE64_EXFIL_PATTERNS +
            self.DOCUMENT_MONITORING_PATTERNS +
            self.WORKSPACE_ACTIVITY_PATTERNS +
            self.HTTP_ENDPOINT_PATTERNS +
            self.TELEMETRY_ABUSE_PATTERNS +
            # Anti-evasion pattern sets
            self.VSCODE_API_EVASION_PATTERNS +
            self.INDIRECT_CODE_EXECUTION_PATTERNS +
            self.EVASION_FILE_ACCESS_PATTERNS +
            self.EVASION_NETWORK_PATTERNS +
            self.EVASION_OBFUSCATION_PATTERNS +
            self.EVASION_FINGERPRINT_PATTERNS +
            self.MODULE_ALIASING_PATTERNS +
            # V2 Capability detection
            self.CAPABILITY_PATTERNS
        )

        # File cache to avoid re-reading
        self._file_cache = {}

    def analyze_extension(self, extension_dir, metadata=None):
        """
        Full four-layer security analysis of a VSCode extension.

        Args:
            extension_dir: Path to extracted extension directory
            metadata: Optional marketplace metadata dict

        Returns:
            dict: Comprehensive analysis results
        """
        extension_dir = Path(extension_dir)

        # Read package.json (the VSCode equivalent of manifest.json)
        pkg = self._read_package_json(extension_dir)
        if not pkg:
            return None

        # Resolve %placeholder% values from package.nls.json (VSCode i18n)
        self._resolve_nls(pkg, extension_dir)

        ext_id = f"{pkg.get('publisher', 'unknown')}.{pkg.get('name', 'unknown')}"
        results = {
            'extension_type': 'vscode',
            'name': pkg.get('displayName', pkg.get('name', 'Unknown')),
            'identifier': ext_id,
            'extension_id': ext_id,
            'version': pkg.get('version', 'Unknown'),
            'description': pkg.get('description', ''),
            'publisher': pkg.get('publisher', 'Unknown'),
            'engines': pkg.get('engines', {}),
            'store_metadata': metadata or {},
        }

        # Layer 1: Metadata & Publisher Analysis
        print("[Layer 1] Metadata & publisher analysis...")
        layer1 = self._analyze_metadata(pkg, metadata)
        results['metadata_risk'] = layer1

        # Layer 1.5: Deep package.json inspection (suspicious URLs, publisher mismatch)
        print("[Layer 1.5] Deep package.json inspection...")
        pkg_deep = self._deep_inspect_package_json(pkg, extension_dir)
        results['package_json_deep'] = pkg_deep
        if pkg_deep['findings']:
            critical_pkg = [f for f in pkg_deep['findings'] if f['severity'] == 'critical']
            if critical_pkg:
                print(f"    [!] {len(critical_pkg)} CRITICAL package.json finding(s)")
            for f in pkg_deep['findings'][:3]:
                print(f"    [{f['severity'].upper()}] {f['name']}")

        # Layer 2: Supply Chain Security
        print("[Layer 2] Supply chain security...")
        layer2 = self._analyze_supply_chain(extension_dir, pkg)
        results['supply_chain'] = layer2

        # Layer 3: Deep Code Analysis
        print("[Layer 3] Deep code analysis & behavioral profiling...")
        layer3 = self._analyze_code(extension_dir, pkg)
        results['code_analysis'] = layer3
        results['malicious_patterns'] = layer3.get('all_findings', [])

        # Layer 3.5: HTML/Webview Analysis
        print("[Layer 3.5] HTML/webview security analysis...")
        try:
            from vscode_html_analyzer import VSCodeHTMLAnalyzer
            html_analyzer = VSCodeHTMLAnalyzer()
            html_results = html_analyzer.analyze_html_files(extension_dir)
            results['html_analysis'] = html_results

            # Merge HTML findings into all_findings and re-run correlation engine
            if html_results.get('findings'):
                results['malicious_patterns'].extend(html_results['findings'])
                layer3['all_findings'].extend(html_results['findings'])

                # Re-run behavioral correlations with HTML findings included
                # (initial correlations in _analyze_code ran before HTML merge)
                existing_corr_types = {
                    f.get('attack_type') for f in layer3['all_findings']
                    if f.get('category') == 'behavioral_correlation'
                }
                new_correlations = self._correlate_behaviors(layer3['all_findings'], pkg)
                for c in new_correlations:
                    if c.get('attack_type') not in existing_corr_types:
                        layer3['all_findings'].append(c)
                        results['malicious_patterns'].append(c)

                # Rebuild category/severity groups
                layer3['findings_by_category'] = self._group_by_category(layer3['all_findings'])
                layer3['findings_by_severity'] = self._group_by_severity(layer3['all_findings'])

                critical_html = [f for f in html_results['findings'] if f['severity'] == 'critical']
                if critical_html:
                    print(f"    [!] {len(critical_html)} CRITICAL webview finding(s)")
                    for f in critical_html[:3]:
                        print(f"    [{f['severity'].upper()}] {f['name']} in {f['file']}")
                else:
                    print(f"    {len(html_results['findings'])} HTML finding(s)")
            else:
                print("    No HTML/webview security issues found")
        except ImportError:
            results['html_analysis'] = {'findings': [], 'files_scanned': 0}
            print("    HTML analyzer not available")

        # Extract permissions-like data from VSCode contributes and API usage
        results['permissions'] = self._extract_permissions(pkg, layer3)

        # Layer 4: Risk Scoring
        print("[Layer 4] Risk scoring...")
        risk = self._calculate_risk_score(results)
        results['risk_score'] = risk['score']
        results['risk_level'] = risk['level']
        results['risk_breakdown'] = risk['breakdown']
        results['positive_signals'] = risk.get('positive_signals', {})
        results['risk_classification'] = risk.get('classification', {})

        classification = risk.get('classification', {})
        if classification:
            cls = classification.get('classification', '')
            print(f"    Classification: {cls}")
            if risk.get('positive_signals', {}).get('count', 0) > 0:
                pos = risk['positive_signals']
                print(f"    Positive signals: {pos['count']} detected (score reduced by {pos['reduction']})")

        # Module usage summary
        results['module_usage'] = layer3.get('module_usage', {})
        results['external_urls'] = layer3.get('external_urls', [])

        return results

    # ──────────────────────────────────────────────────────────────────────
    # Layer 1: Metadata & Publisher Analysis
    # ──────────────────────────────────────────────────────────────────────
    def _analyze_metadata(self, pkg, metadata):
        """Assess risk from metadata and publisher information"""
        findings = []
        risk_score = 0

        # Activation events analysis
        activation_events = pkg.get('activationEvents', [])
        for event in activation_events:
            event_key = event.split(':')[0] if ':' in event else event
            if event_key in self.RISKY_ACTIVATION_EVENTS:
                # * and onDebug = high impact; onStartupFinished is common for server/dev extensions
                high_impact = event_key in ('*', 'onDebug')
                findings.append({
                    'type': 'risky_activation',
                    'severity': 'high' if high_impact else 'medium',
                    'detail': f"Activation event '{event}': {self.RISKY_ACTIVATION_EVENTS[event_key]}",
                    'event': event
                })
                risk_score += 3 if event_key == '*' else (2 if high_impact else 1)

        # Wildcard activation (implicit via package.json with no explicit events)
        if not activation_events:
            # Modern VS Code: no activationEvents means activate on relevant contributes
            pass
        elif '*' in activation_events:
            risk_score += 3

        # Sensitive contributions
        contributes = pkg.get('contributes', {})
        for contrib_key, desc in self.SENSITIVE_CONTRIBUTIONS.items():
            if contrib_key in contributes:
                findings.append({
                    'type': 'sensitive_contribution',
                    'severity': 'medium',
                    'detail': f"Contributes '{contrib_key}': {desc}",
                    'contribution': contrib_key
                })
                risk_score += 1

        # Known-vulnerable extension identifiers (CVE-backed research)
        ext_identifier = f"{pkg.get('publisher', 'unknown')}.{pkg.get('name', 'unknown')}"
        if ext_identifier in self.KNOWN_VULNERABLE_EXTENSIONS:
            vuln = self.KNOWN_VULNERABLE_EXTENSIONS[ext_identifier]
            findings.append({
                'type': 'known_vulnerable_extension',
                'severity': vuln.get('severity', 'critical'),
                'detail': (
                    f"{ext_identifier} is affected by {vuln.get('cve', 'a published vulnerability')}: "
                    f"{vuln.get('description', '')}"
                ),
                'identifier': ext_identifier,
                'cve': vuln.get('cve'),
                'reference': vuln.get('reference'),
                'risk_context': vuln.get('risk_context'),
                'mitigation_note': vuln.get('mitigation_note'),
            })
            # Immediately raise metadata risk close to maximum for known-vulnerable extensions
            risk_score = max(risk_score, 8)

        # Publisher analysis (from marketplace metadata)
        if metadata:
            install_count = metadata.get('install_count', 0) or 0
            if metadata.get('risk_signals', {}).get('unverified_publisher'):
                # Do not flag unverified when install count is very high (reputation signal)
                if install_count < 1_000_000:
                    findings.append({
                        'type': 'unverified_publisher',
                        'severity': 'medium',
                        'detail': 'Publisher domain is not verified'
                    })
                    risk_score += 1

            if metadata.get('risk_signals', {}).get('low_adoption'):
                findings.append({
                    'type': 'low_adoption',
                    'severity': 'medium',
                    'detail': f"Low install count (<{self.LOW_ADOPTION_THRESHOLD})"
                })
                risk_score += 1

            if metadata.get('risk_signals', {}).get('few_ratings'):
                findings.append({
                    'type': 'few_ratings',
                    'severity': 'low',
                    'detail': f"Very few ratings (<{self.FEW_RATINGS_THRESHOLD})"
                })

        return {
            'findings': findings,
            'risk_score': min(risk_score, 10),
            'activation_events': activation_events,
            'contributes': list(contributes.keys())
        }

    # ──────────────────────────────────────────────────────────────────────
    # Layer 2: Supply Chain Security
    # ──────────────────────────────────────────────────────────────────────
    def _analyze_supply_chain(self, extension_dir, pkg):
        """Analyze dependency tree for supply chain risks"""
        findings = []
        risk_score = 0

        deps = pkg.get('dependencies', {})
        dev_deps = pkg.get('devDependencies', {})
        all_deps = {**deps, **dev_deps}

        # Check for known suspicious packages
        for dep_name in deps:
            if dep_name in self.SUSPICIOUS_PACKAGES:
                findings.append({
                    'type': 'known_malicious_package',
                    'severity': 'critical',
                    'package': dep_name,
                    'detail': self.SUSPICIOUS_PACKAGES[dep_name],
                    'version': deps[dep_name]
                })
                risk_score += 5

        # Check for excessively broad version ranges (supply chain risk)
        for dep_name, version_spec in deps.items():
            if version_spec.startswith('*') or version_spec == 'latest':
                findings.append({
                    'type': 'wildcard_dependency',
                    'severity': 'medium',
                    'package': dep_name,
                    'detail': f"Wildcard version '{version_spec}' - accepts any version (supply chain risk)",
                    'version': version_spec
                })
                risk_score += 1

        # Typosquatting detection on production dependencies
        for dep_name in deps:
            typosquat = self._check_typosquatting(dep_name)
            if typosquat:
                findings.append(typosquat)
                risk_score += 2

        # Check bundled node_modules for size anomalies
        # Use os.walk instead of rglob for performance on large dependency trees
        node_modules = extension_dir / 'node_modules'
        if node_modules.exists():
            bundled_count = sum(1 for p in node_modules.iterdir() if p.is_dir() and not p.name.startswith('.'))
            total_size = 0
            native_exts = {'.node', '.dll', '.so', '.dylib', '.exe'}
            native_files = []

            for dirpath, _dirnames, filenames in os.walk(node_modules):
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        total_size += os.path.getsize(fpath)
                    except OSError:
                        pass
                    if os.path.splitext(fname)[1].lower() in native_exts:
                        native_files.append(os.path.relpath(fpath, str(extension_dir)))

            size_mb = total_size / (1024 * 1024)

            findings.append({
                'type': 'bundled_node_modules',
                'severity': 'info',
                'detail': f"{bundled_count} bundled packages ({size_mb:.1f} MB)",
                'count': bundled_count,
                'size_mb': round(size_mb, 1)
            })

            if size_mb > 50:
                findings.append({
                    'type': 'large_node_modules',
                    'severity': 'medium',
                    'detail': f"Very large bundled dependencies ({size_mb:.1f} MB) - difficult to audit"
                })
                risk_score += 1

            if native_files:
                findings.append({
                    'type': 'native_binaries',
                    'severity': 'high',
                    'detail': f"{len(native_files)} native binary file(s) found",
                    'files': native_files[:10]
                })
                risk_score += 2

        # Check for postinstall scripts (supply chain execution)
        scripts = pkg.get('scripts', {})
        dangerous_scripts = ['postinstall', 'preinstall', 'install', 'prepare']
        benign_lifecycle_commands = {
            'husky install', 'husky', 'ngcc', 'patch-package',
            'electron-builder install-app-deps', 'node-gyp rebuild',
            'npm run build', 'tsc', 'tsc -p', 'webpack', 'rollup',
            'esbuild', 'rimraf', 'mkdirp', 'ncp',
        }
        for script_name in dangerous_scripts:
            if script_name in scripts:
                script_content = scripts[script_name]
                # Downgrade to info if the script runs a well-known benign tool
                severity = 'high'
                if any(script_content.strip().startswith(b) for b in benign_lifecycle_commands):
                    severity = 'info'
                findings.append({
                    'type': 'lifecycle_script',
                    'severity': severity,
                    'detail': f"'{script_name}' script: {script_content[:100]}",
                    'script_name': script_name,
                    'script_content': script_content
                })
                risk_score += 2

        # Dependency CVE scan (OSV API) – declared/transitive deps from package.json
        dependency_vulns = []
        try:
            from dependency_vuln_scanner import scan_dependencies
            dep_scan = scan_dependencies(pkg, extension_dir)
            dependency_vulns = dep_scan.get('dependency_vulns', [])
            findings.extend(dep_scan.get('findings', []))
            risk_score += dep_scan.get('risk_delta', 0)
        except Exception:
            pass

        # Bundled JS scan (Retire.js) – vulnerable libraries inside compiled/bundled JS
        bundled_js_vulns = []
        try:
            from retirejs_scanner import scan_bundled_js
            retire_result = scan_bundled_js(extension_dir)
            bundled_js_vulns = retire_result.get('bundled_js_vulns', [])
            findings.extend(retire_result.get('findings', []))
            risk_score += retire_result.get('risk_delta', 0)
        except Exception:
            pass

        return {
            'findings': findings,
            'risk_score': min(risk_score, 10),
            'dependency_count': len(deps),
            'dev_dependency_count': len(dev_deps),
            'has_node_modules': (extension_dir / 'node_modules').exists(),
            'dependency_vulns': dependency_vulns,
            'bundled_js_vulns': bundled_js_vulns,
        }

    # ──────────────────────────────────────────────────────────────────────
    # Layer 3: Deep Code Analysis & Behavioral Profiling
    # ──────────────────────────────────────────────────────────────────────
    def _analyze_code(self, extension_dir, pkg):
        """Deep static analysis of all JavaScript/TypeScript source files"""
        all_findings = []
        module_usage = defaultdict(list)
        external_urls = []
        file_entropies = {}

        # Collect source files, skipping node_modules entirely to avoid
        # walking thousands of dependency files (already audited in supply chain)
        js_extensions = {'.js', '.mjs', '.cjs', '.ts'}
        js_files = self._walk_skip_node_modules(extension_dir, js_extensions)

        _agent_debug_log(
            hypothesis_id="H1_file_loop",
            location="vscode_analyzer._analyze_code:pre_loop",
            message="Starting VSCode code analysis file loop",
            data={
                "files_count": len(js_files),
                "extension_dir": str(extension_dir),
            },
        )

        print(f"    Scanning {len(js_files)} source file(s)...")

        try:
            from tqdm import tqdm
            file_iter = tqdm(js_files, desc="    Code analysis", unit="file", leave=False)
        except ImportError:
            file_iter = js_files

        # Max bytes to scan per file. Lower cap to avoid regex backtracking on huge content.
        MAX_SCAN_SIZE = 384 * 1024  # 384KB
        # Chunk size for parallel scan; chunks scanned in parallel to avoid single 45s hang.
        CHUNK_SIZE = 128 * 1024  # 128KB per chunk
        CHUNK_SCAN_TIMEOUT = 18  # seconds per chunk
        MAX_CHUNK_WORKERS = 4
        # Per-file timeout (seconds); if whole file still hangs, skip and continue
        FILE_SCAN_TIMEOUT = 50

        for idx, js_file in enumerate(file_iter):
            try:
                try:
                    size_bytes = js_file.stat().st_size
                except OSError:
                    size_bytes = -1

                _agent_debug_log(
                    hypothesis_id="H1_file_loop",
                    location="vscode_analyzer._analyze_code:file_start",
                    message="Analyzing VSCode source file",
                    data={
                        "index": idx,
                        "path": str(js_file),
                        "size_bytes": size_bytes,
                    },
                )

                relative_path = str(js_file.relative_to(extension_dir))
                path_lower = relative_path.replace("\\", "/").lower()

                # Heuristic: skip large library/vendor/bundle outputs entirely.
                file_name_lower = js_file.name.lower()
                if size_bytes > 500_000 and (
                    file_name_lower.endswith(".min.js")
                    or file_name_lower.endswith(".min.cjs")
                    or file_name_lower.endswith(".min.mjs")
                    or "mermaid" in file_name_lower
                    or "bundle" in file_name_lower
                    or "vendor" in file_name_lower
                    or "chunk-" in file_name_lower
                    or "polyfill" in file_name_lower
                ) or size_bytes > 2_000_000:
                    _agent_debug_log(
                        hypothesis_id="H1_file_loop",
                        location="vscode_analyzer._analyze_code:file_skipped_large_library",
                        message="Skipping large/minified library file from pattern scan",
                        data={
                            "index": idx,
                            "path": str(js_file),
                            "size_bytes": size_bytes,
                        },
                    )
                    continue

                # Skip large compiled/bundled output under dist/ or out/ (supply chain covers deps).
                if size_bytes > 350_000 and ("/dist/" in path_lower or "/out/" in path_lower or path_lower.startswith("dist/") or path_lower.startswith("out/")):
                    continue

                # For large files, read only first MAX_SCAN_SIZE to avoid slow read + regex on huge content
                content = self._read_file(js_file, max_bytes=MAX_SCAN_SIZE if (size_bytes > MAX_SCAN_SIZE) else None)
                if not content:
                    continue

                # Content is already truncated when file is large (from _read_file max_bytes)
                if len(content) > MAX_SCAN_SIZE:
                    content = content[:MAX_SCAN_SIZE]

                def _process_one_file():
                    newlines = self._build_line_index(content)
                    # Chunked parallel scan for large content to avoid timeout from 100+ regex over 384KB
                    if len(content) > CHUNK_SIZE:
                        file_findings = self._scan_patterns_chunked(
                            content, relative_path, newlines,
                            chunk_size=CHUNK_SIZE,
                            chunk_timeout=CHUNK_SCAN_TIMEOUT,
                            max_workers=MAX_CHUNK_WORKERS,
                        )
                    else:
                        file_findings = self._scan_patterns(content, relative_path, newlines)
                    mods = self._analyze_imports(content, relative_path, newlines)
                    urls = self._extract_urls(content, relative_path, newlines)
                    ent = self._calculate_entropy(content)
                    return newlines, file_findings, mods, urls, ent

                try:
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                        fut = ex.submit(_process_one_file)
                        newlines, file_findings, file_modules, file_urls, entropy = fut.result(timeout=FILE_SCAN_TIMEOUT)
                except concurrent.futures.TimeoutError:
                    print(f"    [timeout] Skipped after {FILE_SCAN_TIMEOUT}s: {relative_path}")
                    continue  # skip this file and continue with next
                except Exception:
                    raise

                all_findings.extend(file_findings)
                for category, modules in file_modules.items():
                    module_usage[category].extend(modules)
                external_urls.extend(file_urls)

                # 4. Shannon entropy (obfuscation detection)
                if entropy > 5.5:  # High entropy threshold
                    file_entropies[relative_path] = entropy
                    if entropy > 6.5:
                        path_type = 'dependency' if self._is_dependency_path(relative_path) else 'app'
                        all_findings.append({
                            'name': 'High entropy file',
                            'severity': 'medium',
                            'description': f'File has very high entropy ({entropy:.2f}) - possible obfuscation/packed code',
                            'category': 'obfuscation',
                            'file': relative_path,
                            'line': 0,
                            'evidence': f'Shannon entropy: {entropy:.2f} (threshold: 6.5)',
                            'path_type': path_type,
                        })

                _agent_debug_log(
                    hypothesis_id="H1_file_loop",
                    location="vscode_analyzer._analyze_code:file_done",
                    message="Finished VSCode source file",
                    data={
                        "index": idx,
                        "path": str(js_file),
                        "size_bytes": size_bytes,
                        "entropy": entropy,
                    },
                )

            except Exception as e:
                _agent_debug_log(
                    hypothesis_id="H1_file_loop",
                    location="vscode_analyzer._analyze_code:file_error",
                    message="Error analyzing VSCode source file",
                    data={
                        "index": idx,
                        "path": str(js_file),
                        "error": str(e),
                    },
                )
                continue

        # Apply false positive filtering before correlations
        all_findings, suppressed = self._filter_vscode_false_positives(all_findings, extension_dir)

        # Enhanced behavioral correlation engine (8 rules)
        correlations = self._correlate_behaviors(all_findings, pkg)
        all_findings.extend(correlations)

        return {
            'all_findings': all_findings,
            'module_usage': dict(module_usage),
            'external_urls': external_urls,
            'file_entropies': file_entropies,
            'files_scanned': len(js_files),
            'findings_by_category': self._group_by_category(all_findings),
            'findings_by_severity': self._group_by_severity(all_findings),
            'suppressed_false_positives': len(suppressed),
        }

    def _is_dependency_path(self, file_path):
        """True if file is under node_modules or dependencies/ (third-party code)."""
        path_norm = file_path.replace('\\', '/')
        return 'node_modules' in path_norm or '/dependencies/' in path_norm or path_norm.startswith('dependencies/')

    @staticmethod
    def _build_line_index(content):
        """Build a sorted list of newline positions for O(log n) line-number lookups."""
        newlines = []
        pos = -1
        while True:
            pos = content.find('\n', pos + 1)
            if pos == -1:
                break
            newlines.append(pos)
        return newlines

    @staticmethod
    def _offset_to_line(newlines, offset):
        """Convert a byte offset to a 1-based line number using binary search."""
        import bisect
        return bisect.bisect_right(newlines, offset) + 1

    # Cap matches per pattern per file to avoid runaway time on files with
    # hundreds of the same finding (e.g. require() in a bundle). Security
    # value is in detecting the presence of the pattern, not every occurrence.
    MAX_MATCHES_PER_PATTERN_PER_FILE = 20

    def _scan_patterns(self, content, file_path, newlines=None, offset_base=0):
        """Scan file content against all pattern categories. offset_base added to match positions for line lookup (for chunked scan)."""
        findings = []
        path_type = 'dependency' if self._is_dependency_path(file_path) else 'app'

        if newlines is None:
            newlines = self._build_line_index(content)

        for pattern_def in self.all_patterns:
            match_count = 0
            for match in pattern_def['pattern'].finditer(content):
                if match_count >= self.MAX_MATCHES_PER_PATTERN_PER_FILE:
                    break
                match_count += 1
                line_num = self._offset_to_line(newlines, offset_base + match.start())
                start = max(0, match.start() - 40)
                end = min(len(content), match.end() + 40)
                context = content[start:end].replace('\n', ' ').strip()
                evidence = context[:200]

                # Skip Plaintext HTTP when match is XML/HTML namespace URL (w3.org, etc.)
                if pattern_def['name'] == 'Plaintext HTTP endpoint (not HTTPS)':
                    if any(ind in evidence for ind in self.HTTP_NAMESPACE_URL_INDICATORS):
                        continue

                # Skip hex-only strings falsely matched as base64 (e.g. D3/Vega color palettes)
                if pattern_def.get('_post_validate') == 'base64_not_hex':
                    matched_str = match.group(0).strip('"\'')
                    if all(c in '0123456789abcdefABCDEF' for c in matched_str.rstrip('=')):
                        continue

                severity = pattern_def['severity']
                if path_type == 'dependency' and pattern_def['category'] == 'webview_risk':
                    severity = 'medium'

                findings.append({
                    'name': pattern_def['name'],
                    'severity': severity,
                    'description': pattern_def['description'],
                    'category': pattern_def['category'],
                    'file': file_path,
                    'line': line_num,
                    'evidence': evidence,
                    'path_type': path_type,
                })

        return findings

    def _scan_patterns_chunked(self, content, file_path, newlines, chunk_size, chunk_timeout, max_workers):
        """Scan large content by splitting into chunks and running _scan_patterns per chunk in parallel. Reduces timeout risk from 100+ regex over one big string."""
        import concurrent.futures
        chunks = []
        start = 0
        while start < len(content):
            end = min(start + chunk_size, len(content))
            chunks.append((start, end, content[start:end]))
            start = end
        if not chunks:
            return []
        all_findings = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            future_to_chunk = {}
            for start, end, chunk in chunks:
                fut = ex.submit(
                    self._scan_patterns,
                    chunk,
                    file_path,
                    newlines,
                    offset_base=start,
                )
                future_to_chunk[fut] = (start, end)
            for fut in concurrent.futures.as_completed(future_to_chunk):
                start, end = future_to_chunk[fut]
                try:
                    findings = fut.result(timeout=chunk_timeout)
                    all_findings.extend(findings)
                except concurrent.futures.TimeoutError:
                    pass  # skip this chunk, keep others
                except Exception:
                    raise
        return all_findings

    def _analyze_imports(self, content, file_path, newlines=None):
        """Analyze require() and import statements to identify sensitive module usage"""
        usage = defaultdict(list)
        if newlines is None:
            newlines = self._build_line_index(content)

        # require('module') pattern
        require_re = re.compile(r'require\s*\(\s*["\']([^"\']+)["\']\s*\)')
        # import ... from 'module' pattern
        import_re = re.compile(r'(?:import|from)\s+[^;]+\s+from\s+["\']([^"\']+)["\']')

        for regex in [require_re, import_re]:
            for match in regex.finditer(content):
                module_name = match.group(1)
                # Check against sensitive module categories
                for category, modules in self.SENSITIVE_MODULES.items():
                    if module_name in modules or module_name.split('/')[0] in modules:
                        line_num = self._offset_to_line(newlines, match.start())
                        usage[category].append({
                            'module': module_name,
                            'file': file_path,
                            'line': line_num
                        })

        return dict(usage)

    def _extract_urls(self, content, file_path, newlines=None):
        """Extract external URLs from source code"""
        urls = []
        if newlines is None:
            newlines = self._build_line_index(content)
        url_re = re.compile(r'["\'](?:https?://[^"\'\\]{5,})["\']')

        for match in url_re.finditer(content):
            url = match.group(0).strip('"\'')
            # Skip common safe/internal URLs
            if any(safe in url for safe in [
                'schemas.microsoft.com', 'github.com/microsoft',
                'code.visualstudio.com', 'localhost', '127.0.0.1',
                'example.com', 'schema.org', 'w3.org',
            ]):
                continue

            line_num = self._offset_to_line(newlines, match.start())
            urls.append({
                'url': url,
                'file': file_path,
                'line': line_num
            })

        return urls

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of string data"""
        if not data:
            return 0
        freq = defaultdict(int)
        for char in data:
            freq[char] += 1
        length = len(data)
        entropy = 0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 2)

    def _group_by_category(self, findings):
        """Group findings by category"""
        groups = defaultdict(list)
        for f in findings:
            groups[f.get('category', 'unknown')].append(f)
        return dict(groups)

    def _group_by_severity(self, findings):
        """Group findings by severity"""
        groups = defaultdict(int)
        for f in findings:
            groups[f.get('severity', 'unknown')] += 1
        return dict(groups)

    # ──────────────────────────────────────────────────────────────────────
    # Positive signal analysis (reduces false positives)
    # ──────────────────────────────────────────────────────────────────────
    def _calculate_positive_signals(self, results):
        """
        Detect positive (benign) signals that indicate the extension is
        likely legitimate despite having high-risk capabilities.

        Context-aware: signals are suppressed when contradictory attack
        indicators are present (e.g., "no_obfuscation" is not awarded
        when indirect eval code execution is detected).

        Returns:
            dict with 'signals' list and 'reduction' score (0 to 1.5)
        """
        signals = []
        reduction = 0.0

        code_analysis = results.get('code_analysis', {})
        all_findings = code_analysis.get('all_findings', [])
        module_usage = code_analysis.get('module_usage', {})
        findings_by_cat = code_analysis.get('findings_by_category', {})

        # Pre-compute attack context for suppression logic
        has_code_execution = 'code_execution' in findings_by_cat
        has_auth_abuse = 'auth_token_theft' in findings_by_cat or 'browser_exfil' in findings_by_cat
        has_persistence = len(findings_by_cat.get('persistence', [])) >= 3
        has_cmd_injection = 'command_injection' in findings_by_cat
        has_terminal_hijack = 'terminal_hijack' in findings_by_cat

        # Collect all correlation attack types
        corr_attack_types = {
            f.get('attack_type') for f in all_findings
            if f.get('category') == 'behavioral_correlation' and f.get('attack_type')
        }
        has_critical_correlation = any(
            f.get('category') == 'behavioral_correlation' and f.get('severity') == 'critical'
            for f in all_findings
        )

        # 1. No network access: extension stays local (always valid)
        has_network = (
            'network' in module_usage or
            'network_exfil' in findings_by_cat or
            'insecure_endpoint' in findings_by_cat
        )
        if not has_network:
            signals.append({
                'signal': 'no_network_access',
                'description': 'Extension has no network capabilities - data stays local',
                'weight': 0.5
            })
            reduction += 0.5

        # 2. No obfuscation: code is transparent
        # Suppressed if code_execution detected (indirect eval IS evasion)
        has_obfuscation = 'obfuscation' in findings_by_cat or 'evasion_technique' in findings_by_cat
        if not has_obfuscation and not has_code_execution:
            signals.append({
                'signal': 'no_obfuscation',
                'description': 'No code obfuscation or evasion techniques detected',
                'weight': 0.3
            })
            reduction += 0.3

        # 3. No credential theft patterns
        # Suppressed if auth_token_theft or heavy persistence (C2 config storage)
        has_cred_theft = 'credential_theft' in findings_by_cat or 'settings_theft' in findings_by_cat
        if not has_cred_theft and not has_auth_abuse and not has_persistence:
            signals.append({
                'signal': 'no_credential_access',
                'description': 'No access to credential files, SSH keys, or token stores',
                'weight': 0.3
            })
            reduction += 0.3

        # 4. Scoped activation (not wildcard)
        # Suppressed if any critical-severity behavioral correlation exists
        # (scoped activation is a deliberate evasion technique in staged payloads)
        activation_events = results.get('metadata_risk', {}).get('activation_events', [])
        if activation_events and '*' not in activation_events and not has_critical_correlation:
            signals.append({
                'signal': 'scoped_activation',
                'description': 'Extension activates only on specific events, not wildcard',
                'weight': 0.2
            })
            reduction += 0.2

        # 5. No exfiltration / malice patterns
        # Expanded to cover all malicious correlation types
        malice_types = {
            'code_exfiltration', 'continuous_surveillance', 'keylogging',
            'staged_payload', 'oauth_token_theft', 'credential_exfiltration',
            'multi_channel_c2', 'c2_persistence', 'fingerprint_exfil',
            'wallet_hijacking', 'silent_rce', 'evasive_execution',
            'stealth_backdoor', 'remote_agent', 'stealth_execution',
            'clipboard_surveillance', 'clipboard_exfil', 'identity_harvesting',
            'remote_control'
        }
        has_malice_combo = bool(corr_attack_types & malice_types)
        if not has_malice_combo and not has_cmd_injection and not has_terminal_hijack:
            signals.append({
                'signal': 'no_exfiltration_pattern',
                'description': 'No compound attack patterns detected',
                'weight': 0.2
            })
            reduction += 0.2

        # Cap total reduction at 1.5
        reduction = min(1.5, reduction)

        return {
            'signals': signals,
            'reduction': round(reduction, 1),
            'count': len(signals)
        }

    # ──────────────────────────────────────────────────────────────────────
    # Layer 4: Risk Scoring
    # ──────────────────────────────────────────────────────────────────────
    def _calculate_risk_score(self, results):
        """
        Calculate aggregate risk score (0-10 scale) using 5-component model.

        Restructured so supply chain (vulnerable dependencies) can contribute up to 5 points:
        - If any dependency or bundled-JS vulnerability is found → supply chain = 5 (MEDIUM floor).
        - Remaining 5 points from: metadata, code analysis, behavioral correlations, infrastructure
          (permissions, malicious patterns, HTML/pkg findings).

        Components (total 10):
          Supply Chain:            0-5  (5 when any dep/bundled vuln; else 0)
          Metadata & Publisher:    0-1
          Code Analysis:           0-2
          Behavioral Correlations: 0-1.5
          Infrastructure:          0-0.5
        """
        breakdown = {}
        total_score = 0
        supply = results.get('supply_chain', {})
        dependency_vulns = supply.get('dependency_vulns', [])
        bundled_js_vulns = supply.get('bundled_js_vulns', [])
        has_vuln_dep = bool(dependency_vulns or bundled_js_vulns)
        vuln_count = sum(len(d.get('vulns', [])) for d in dependency_vulns)
        vuln_count += sum(len(b.get('vulns', [])) for b in bundled_js_vulns)

        # ── 1. Supply Chain (0-5) ────────────────────────────────────────
        # Vulnerable dependency or bundled JS → 5/5 (supply chain risk = MEDIUM by itself)
        if has_vuln_dep:
            supply_score = 5.0
        else:
            supply_raw = supply.get('risk_score', 0)
            supply_score = min(2.0, supply_raw / 5)
            if supply.get('has_node_modules') and supply.get('dependency_count', 0) > 0:
                supply_score = max(0.3, supply_score)
            supply_score = min(5.0, supply_score * 2.5)
        breakdown['supply_chain'] = round(supply_score, 1)
        total_score += supply_score

        # ── 2. Metadata & Publisher (0-1) ────────────────────────────────
        pkg_deep = results.get('package_json_deep', {})
        meta_raw = results.get('metadata_risk', {}).get('risk_score', 0)
        meta_score = min(1.0, (meta_raw / 5) * 0.5)
        for f in pkg_deep.get('findings', []):
            if f.get('severity') == 'critical':
                meta_score = min(1.0, meta_score + 0.25)
            elif f.get('severity') == 'high':
                meta_score = min(1.0, meta_score + 0.15)
        breakdown['metadata_publisher'] = round(meta_score, 1)
        total_score += meta_score

        # ── 3. Code Analysis (0-2) ──────────────────────────────────────
        code_findings = results.get('code_analysis', {}).get('all_findings', [])
        code_only = [f for f in code_findings
                     if f.get('category') != 'behavioral_correlation'
                     and f.get('category') not in ('hidden_iframe', 'analytics_injection', 'webview_xss')]
        if code_only:
            critical_count = sum(1 for f in code_only if f.get('severity') == 'critical')
            high_count = sum(1 for f in code_only if f.get('severity') == 'high')
            severity_score = min(1.75, critical_count * 0.5 + high_count * 0.2)
            density_bonus = 0.5 if len(code_only) > 20 else (0.25 if len(code_only) > 10 else 0)
            code_score = min(2.0, severity_score + density_bonus)
        else:
            code_score = 0
        breakdown['code_analysis'] = round(code_score, 1)
        total_score += code_score

        # ── 4. Behavioral Correlations (0-1.5) ─────────────────────────────
        correlations = [f for f in code_findings if f.get('category') == 'behavioral_correlation']
        corr_score = 0
        for corr in correlations:
            sev = corr.get('severity', 'medium')
            if sev == 'critical':
                corr_score += 0.75
            elif sev == 'high':
                corr_score += 0.4
            else:
                corr_score += 0.15
        corr_score = min(1.5, corr_score)
        breakdown['behavioral_correlations'] = round(corr_score, 1)
        total_score += corr_score

        # ── 5. Infrastructure (0-0.5) ─────────────────────────────────────
        infra_score = 0
        html_findings = results.get('html_analysis', {}).get('findings', [])
        if html_findings:
            critical_html = sum(1 for f in html_findings if f.get('severity') == 'critical')
            high_html = sum(1 for f in html_findings if f.get('severity') == 'high')
            if critical_html:
                infra_score += 0.25
            if high_html:
                infra_score += 0.12
            if html_findings:
                infra_score += 0.05
        pkg_deep_findings = pkg_deep.get('findings', [])
        if any(f.get('category', '') == 'package_json_suspicious_url' for f in pkg_deep_findings):
            infra_score += 0.15
        infra_score = min(0.5, infra_score)
        breakdown['infrastructure'] = round(infra_score, 1)
        total_score += infra_score

        # ── 6. Positive signals (reduce score, capped) ─────────────────────
        positive = self._calculate_positive_signals(results)
        pos_reduction = positive['reduction']
        breakdown['positive_signals'] = round(-pos_reduction, 1)
        total_score -= pos_reduction

        # ── 7. Vulnerable dependency floor: at least 5/10 (MEDIUM) ────────
        if has_vuln_dep:
            total_score = max(5.0, total_score)

        # ── 8. Critical-severity malice floor ──────────────────────────
        tier1_attack_types = {
            'staged_payload', 'silent_rce', 'oauth_token_theft',
            'code_exfiltration', 'continuous_surveillance',
            'credential_exfiltration', 'multi_channel_c2',
            'wallet_hijacking', 'keylogging',
            'remote_agent', 'stealth_execution', 'identity_harvesting'
        }
        tier2_attack_types = {
            'stealth_backdoor', 'fingerprint_exfil', 'evasive_execution',
            'c2_persistence', 'credential_leak',
            'clipboard_surveillance', 'clipboard_exfil', 'remote_control'
        }
        corr_attack_types = {
            c.get('attack_type') for c in correlations if c.get('attack_type')
        }
        critical_count_all = sum(1 for f in code_only if f.get('severity') == 'critical')

        if corr_attack_types & tier1_attack_types:
            total_score = max(5.0, total_score)
        elif corr_attack_types & tier2_attack_types:
            total_score = max(4.0, total_score)
        elif critical_count_all >= 3:
            total_score = max(4.0, total_score)
        elif critical_count_all >= 1 and correlations:
            total_score = max(3.0, total_score)

        # ── Final score (0-10) and level ─────────────────────────────────
        final_score = round(max(0, min(10.0, total_score)), 1)

        if final_score >= 8:
            level = 'CRITICAL'
        elif final_score >= 6:
            level = 'HIGH'
        elif final_score >= 5:
            level = 'MEDIUM'
        elif final_score >= 2:
            level = 'LOW'
        else:
            level = 'MINIMAL'

        # Ensure vulnerable dependency always yields at least MEDIUM
        if has_vuln_dep and level in ('MINIMAL', 'LOW'):
            level = 'MEDIUM'

        # ── Nuanced classification ──────────────────────────────────────
        classification = self._classify_risk_intent(
            level, positive, code_findings, results
        )

        return {
            'score': final_score,
            'level': level,
            'breakdown': breakdown,
            'positive_signals': positive,
            'classification': classification
        }

    def _classify_risk_intent(self, level, positive_signals, code_findings, results):
        """
        Classify whether high-risk capabilities indicate malicious intent
        or are justified by the extension's legitimate purpose.

        Returns one of:
          - MALICIOUS_INDICATORS: Multiple suspicious patterns suggesting malicious intent
          - HIGH_CAPABILITY_SUSPICIOUS: High-risk capabilities with some suspicious signals
          - HIGH_CAPABILITY_JUSTIFIED: High-risk capabilities but strong positive signals
          - STANDARD_RISK: Normal extension with moderate capabilities
          - BENIGN: Low-risk extension with no concerning signals
        """
        pos_count = positive_signals.get('count', 0)
        pos_signals = {s['signal'] for s in positive_signals.get('signals', [])}

        # Count suspicion indicators
        has_obfuscation = any(
            f.get('category') in ('obfuscation', 'evasion_technique')
            for f in code_findings
        )
        malice_correlation_types = {
            'code_exfiltration', 'continuous_surveillance', 'stealth_backdoor',
            'keylogging', 'wallet_hijacking', 'staged_payload', 'oauth_token_theft',
            'evasive_execution', 'credential_exfiltration', 'multi_channel_c2',
            'c2_persistence', 'fingerprint_exfil', 'silent_rce',
            'remote_agent', 'stealth_execution', 'clipboard_surveillance',
            'clipboard_exfil', 'identity_harvesting', 'remote_control'
        }
        has_exfil_correlation = any(
            f.get('category') == 'behavioral_correlation' and
            f.get('attack_type') in malice_correlation_types
            for f in code_findings
        )
        has_credential_theft = any(
            f.get('category') in ('credential_theft', 'auth_token_theft', 'settings_theft')
            for f in code_findings
        )
        has_network = 'no_network_access' not in pos_signals
        has_high_capability = any(
            f.get('category') in ('command_injection', 'code_execution', 'terminal_hijack')
            for f in code_findings
        )
        has_auth_abuse = any(
            f.get('category') in ('auth_token_theft', 'browser_exfil')
            for f in code_findings
        )
        has_persistence = sum(
            1 for f in code_findings if f.get('category') == 'persistence'
        ) >= 3
        has_local_server = any(
            f.get('category') == 'local_server' for f in code_findings
        )
        has_identity_harvest = any(
            f.get('category') == 'identity_harvesting' for f in code_findings
        )
        has_clipboard = any(
            f.get('category') == 'clipboard_access' for f in code_findings
        )
        has_remote_orch = any(
            f.get('category') == 'remote_orchestration' for f in code_findings
        )

        suspicion_count = sum([
            has_obfuscation, has_exfil_correlation, has_credential_theft,
            has_network and has_high_capability, has_auth_abuse, has_persistence,
            has_local_server, has_identity_harvest,
            has_clipboard and has_network, has_remote_orch
        ])

        if level in ('CRITICAL', 'HIGH'):
            if suspicion_count >= 2:
                classification = 'MALICIOUS_INDICATORS'
                summary = ('Multiple suspicious patterns detected alongside high-risk capabilities. '
                           'Obfuscation, data exfiltration, or credential theft patterns suggest '
                           'potentially malicious intent. Manual review strongly recommended.')
            elif suspicion_count == 1 or pos_count <= 2:
                classification = 'HIGH_CAPABILITY_SUSPICIOUS'
                summary = ('High-risk capabilities detected with some suspicious signals. '
                           'Extension may be legitimate but warrants careful review of flagged behaviors.')
            else:
                classification = 'HIGH_CAPABILITY_JUSTIFIED'
                summary = ('High-risk capabilities detected but strong positive signals indicate '
                           'legitimate purpose. No obfuscation, no credential theft, behavior '
                           'matches expected extension functionality. Capability is justified '
                           'but users should be aware of the access granted.')
        elif level == 'MEDIUM':
            if suspicion_count >= 2:
                classification = 'HIGH_CAPABILITY_SUSPICIOUS'
                summary = ('Moderate risk level but multiple suspicious patterns detected. '
                           'Extension warrants careful review of flagged behaviors.')
            else:
                classification = 'STANDARD_RISK'
                summary = ('Moderate capabilities detected. Extension uses some sensitive APIs '
                           'but no strong indicators of malicious intent.')
        else:
            classification = 'BENIGN'
            summary = 'Low-risk extension with minimal sensitive capabilities.'

        return {
            'classification': classification,
            'summary': summary,
            'suspicion_indicators': suspicion_count,
            'positive_signal_count': pos_count,
        }

    def _extract_permissions(self, pkg, code_analysis):
        """
        Extract permission-like data from VSCode extension.
        VSCode doesn't have a formal permissions system like Chrome,
        so we infer from API usage and contributes.
        """
        high_risk = []
        medium_risk = []
        low_risk = []

        # From module usage
        module_usage = code_analysis.get('module_usage', {})

        if 'process_execution' in module_usage:
            high_risk.append({
                'permission': 'child_process',
                'description': 'Can execute system commands',
                'evidence': module_usage['process_execution']
            })

        if 'file_access' in module_usage:
            medium_risk.append({
                'permission': 'filesystem',
                'description': 'Can read/write files on disk',
                'evidence': module_usage['file_access']
            })

        if 'network' in module_usage:
            medium_risk.append({
                'permission': 'network',
                'description': 'Can make network requests',
                'evidence': module_usage['network']
            })

        if 'vm' in module_usage:
            high_risk.append({
                'permission': 'vm_execution',
                'description': 'Can execute arbitrary code in VM context',
                'evidence': module_usage['vm']
            })

        if 'os_info' in module_usage:
            low_risk.append({
                'permission': 'os_info',
                'description': 'Can read OS information',
                'evidence': module_usage['os_info']
            })

        # From code findings
        categories = code_analysis.get('findings_by_category', {})
        if 'credential_theft' in categories:
            high_risk.append({
                'permission': 'credential_access',
                'description': 'Accesses credential files/stores',
                'finding_count': len(categories['credential_theft'])
            })

        if 'terminal_hijack' in categories:
            high_risk.append({
                'permission': 'terminal_control',
                'description': 'Creates/controls integrated terminals',
                'finding_count': len(categories['terminal_hijack'])
            })

        if 'document_monitoring' in categories:
            medium_risk.append({
                'permission': 'real_time_document_monitoring',
                'description': 'Monitors text document changes in real time',
                'finding_count': len(categories['document_monitoring'])
            })

        if 'workspace_activity_monitoring' in categories:
            low_risk.append({
                'permission': 'workspace_activity_tracking',
                'description': 'Tracks developer activity (file opens, saves, folder changes, paths)',
                'finding_count': len(categories['workspace_activity_monitoring'])
            })

        # From contributes
        contributes = pkg.get('contributes', {})
        if 'debuggers' in contributes:
            high_risk.append({
                'permission': 'debugger',
                'description': 'Contributes a debugger (can inspect process state)'
            })

        return {
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk,
            'total': len(high_risk) + len(medium_risk) + len(low_risk),
            'all': [p.get('permission', '') for p in high_risk + medium_risk + low_risk]
        }

    # ──────────────────────────────────────────────────────────────────────
    # Deep package.json inspection (suspicious URLs, publisher mismatch)
    # ──────────────────────────────────────────────────────────────────────
    def _deep_inspect_package_json(self, pkg, extension_dir):
        """Deep inspection of package.json for suspicious URLs, configs, and domain mismatches"""
        from urllib.parse import urlparse
        findings = []

        # 1. Scan configuration defaults for hardcoded URLs
        contributes = pkg.get('contributes', {}) or {}
        config = contributes.get('configuration')
        if config is None:
            config = {}
        # Handle both single config (dict) and array format (list of config objects)
        if isinstance(config, list):
            properties = {}
            for c in config:
                if isinstance(c, dict):
                    properties.update((c.get('properties') or {}))
        else:
            properties = (config.get('properties') or {}) if isinstance(config, dict) else {}

        url_pattern = re.compile(r'https?://[^\s"\'<>,]+', re.IGNORECASE)

        for prop_name, prop_def in properties.items():
            if not isinstance(prop_def, dict):
                continue
            default_val = prop_def.get('default', '')
            if not isinstance(default_val, str):
                continue
            urls_in_default = url_pattern.findall(default_val)
            for url in urls_in_default:
                try:
                    parsed = urlparse(url)
                except Exception:
                    continue
                severity = 'medium'
                description = f'Hardcoded URL in config default: {prop_name}'

                if parsed.scheme == 'http':
                    severity = 'high'
                    description = f'PLAINTEXT HTTP URL in config default "{prop_name}" - data sent unencrypted'

                domain = (parsed.netloc or '').lower()
                for tld in self.SUSPICIOUS_TLDS:
                    if domain.endswith(tld):
                        severity = 'critical'
                        description = f'Suspicious TLD ({tld}) in config default "{prop_name}" - untrusted remote endpoint'
                        break

                findings.append({
                    'name': f'Suspicious URL in package.json config: {prop_name}',
                    'severity': severity,
                    'description': description,
                    'category': 'package_json_suspicious_url',
                    'file': 'package.json',
                    'line': 0,
                    'evidence': f'{prop_name} default = {url}'
                })

        # 2. Repository / transparency (Phase 2 triage: GitHub repo present lowers risk)
        repo = pkg.get('repository')
        has_repo = bool(repo and (isinstance(repo, str) or (isinstance(repo, dict) and (repo.get('url') or repo.get('type')))))
        if not has_repo:
            findings.append({
                'name': 'No repository link in package.json',
                'severity': 'low',
                'description': 'No repository URL - reduces transparency and auditability',
                'category': 'package_json_no_repository',
                'file': 'package.json',
                'line': 0,
                'evidence': 'repository field missing or empty'
            })

        # 3. Publisher-domain mismatch
        publisher = pkg.get('publisher', '').lower()
        all_urls_in_pkg = url_pattern.findall(json.dumps(pkg))
        unique_domains = set()
        for url in all_urls_in_pkg:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    unique_domains.add(parsed.netloc.lower())
            except Exception:
                pass

        infra_domains = {
            # Source hosting & Microsoft
            'github.com', 'raw.githubusercontent.com', 'github.io',
            'marketplace.visualstudio.com', 'code.visualstudio.com',
            'vscode.dev', 'microsoft.com', 'aka.ms',
            # CDNs
            'cdn.jsdelivr.net', 'jsdelivr.net', 'cdnjs.cloudflare.com',
            'unpkg.com', 'cdn.skypack.dev', 'esm.sh', 'fastly.net',
            # Package registries
            'npmjs.org', 'npmjs.com', 'www.npmjs.com', 'registry.npmjs.org',
            'pypi.org', 'crates.io',
            # Documentation / standards
            'w3.org', 'www.w3.org', 'schema.org', 'developer.mozilla.org', 'tc39.es',
            # Well-known services commonly integrated by extensions
            'kroki.io', 'plantuml.com', 'latex.codecogs.com', 'mermaid.ink',
            'shields.io', 'img.shields.io', 'badge.fury.io', 'badgen.net',
            'criticmarkup.com',
            # Localhost
            'localhost', '127.0.0.1', '0.0.0.0',
        }
        operational_domains = {d for d in unique_domains
                               if not any(safe in d for safe in infra_domains)}

        for domain in operational_domains:
            parts = domain.split('.')
            domain_base = parts[-2] if len(parts) >= 2 else domain
            if publisher and publisher not in domain and domain_base not in publisher:
                findings.append({
                    'name': f'Publisher-domain mismatch: {publisher} vs {domain}',
                    'severity': 'medium',
                    'description': f'Publisher "{publisher}" does not match operational domain "{domain}"',
                    'category': 'publisher_mismatch',
                    'file': 'package.json',
                    'line': 0,
                    'evidence': f'publisher={publisher}, domain={domain}'
                })

        # 4. Wildcard activation + network dependency = always-on network capable
        activation_events = pkg.get('activationEvents', [])
        deps = list(pkg.get('dependencies', {}).keys())
        network_deps = {'axios', 'got', 'node-fetch', 'superagent', 'request', 'ws', 'socket.io-client'}
        found_net_deps = network_deps.intersection(set(deps))

        if '*' in activation_events and found_net_deps:
            findings.append({
                'name': 'Wildcard activation with network dependency',
                'severity': 'critical',
                'description': 'Extension activates on EVERYTHING and bundles network client - always-on remote communication capable',
                'category': 'package_json_suspicious_url',
                'file': 'package.json',
                'line': 0,
                'evidence': f'activationEvents=["*"], network deps: {found_net_deps}'
            })

        return {'findings': findings}

    # ──────────────────────────────────────────────────────────────────────
    # Enhanced behavioral correlation engine (8 rules)
    # ──────────────────────────────────────────────────────────────────────
    def _correlate_behaviors(self, all_findings, pkg):
        """Detect compound attack patterns from combinations of individual findings"""
        correlations = []
        categories = defaultdict(list)
        for f in all_findings:
            categories[f.get('category', 'unknown')].append(f)

        activation_events = pkg.get('activationEvents', [])
        has_wildcard = '*' in activation_events

        # Network categories (union)
        network = (categories.get('network_exfil', []) +
                   categories.get('insecure_endpoint', []) +
                   categories.get('hidden_iframe', []))

        # 1. File monitoring + base64 + network = potential data exfiltration
        doc_monitoring = categories.get('document_monitoring', [])
        base64_exfil = categories.get('base64_exfil', []) + categories.get('workspace_harvesting', [])
        if doc_monitoring and base64_exfil and network:
            correlations.append({
                'name': 'Potential data exfiltration: file monitoring + base64 encoding + network',
                'severity': 'critical',
                'description': 'Extension monitors file changes, encodes content, and has network access - '
                               'potential data exfiltration capability. Review what data is sent and where.',
                'category': 'behavioral_correlation',
                'file': doc_monitoring[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{doc_monitoring[0]["name"]} | {base64_exfil[0]["name"]} | {network[0]["name"]}',
                'confidence': 'HIGH',
                'attack_type': 'code_exfiltration'
            })

        # 2. Hidden iframe + analytics = fingerprinting capability
        iframe_findings = categories.get('hidden_iframe', [])
        analytics = categories.get('analytics_injection', []) + categories.get('telemetry_abuse', [])
        if iframe_findings and analytics:
            correlations.append({
                'name': 'Fingerprinting capability: hidden iframe + analytics SDK',
                'severity': 'high',
                'description': 'Hidden iframe combined with analytics SDK - likely user fingerprinting and tracking',
                'category': 'behavioral_correlation',
                'file': iframe_findings[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{iframe_findings[0]["name"]} | {analytics[0]["name"]}',
                'confidence': 'HIGH',
                'attack_type': 'fingerprinting'
            })

        # 3. Wildcard activation + doc monitoring + network = potential continuous monitoring
        if has_wildcard and doc_monitoring and network:
            correlations.append({
                'name': 'Potential continuous monitoring: wildcard activation + document events + network',
                'severity': 'critical',
                'description': 'Extension activates on everything, monitors document changes, and has '
                               'network access - review whether data collection is proportionate to functionality',
                'category': 'behavioral_correlation',
                'file': doc_monitoring[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'activationEvents=["*"] + {doc_monitoring[0]["name"]} + {network[0]["name"]}',
                'confidence': 'HIGH',
                'attack_type': 'continuous_surveillance'
            })

        # 4. Token/credential input + plaintext HTTP = credential exposure risk
        cred_input = [f for f in all_findings if any(k in f.get('name', '').lower()
                      for k in ['token', 'credential', 'password', 'auth', 'secret storage'])]
        http_plain = [f for f in all_findings if f.get('category') == 'insecure_endpoint'
                      and 'plaintext' in f.get('description', '').lower()]
        if cred_input and http_plain:
            correlations.append({
                'name': 'Credential exposure risk: auth token handling + plaintext HTTP',
                'severity': 'critical',
                'description': 'Extension handles auth tokens AND uses plaintext HTTP - credentials may be sent unencrypted',
                'category': 'behavioral_correlation',
                'file': cred_input[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{cred_input[0]["name"]} + {http_plain[0]["name"]}',
                'confidence': 'MEDIUM',
                'attack_type': 'credential_leak'
            })

        # 5. Startup/wildcard activation + process execution = RCE capability
        proc_exec = categories.get('command_injection', []) + categories.get('code_execution', [])
        if has_wildcard and proc_exec:
            correlations.append({
                'name': 'RCE capability: wildcard activation + process execution',
                'severity': 'critical',
                'description': 'Extension auto-activates and can execute system commands - review whether command execution is justified',
                'category': 'behavioral_correlation',
                'file': proc_exec[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'activationEvents=["*"] + {proc_exec[0]["name"]}',
                'confidence': 'HIGH',
                'attack_type': 'silent_rce'
            })

        # 6. Obfuscation + network = suspicious obfuscated network activity
        obfuscation = categories.get('obfuscation', [])
        if obfuscation and network:
            correlations.append({
                'name': 'Suspicious pattern: obfuscation + network communication',
                'severity': 'high',
                'description': 'Obfuscated code with network capabilities - may be hiding network activity intent',
                'category': 'behavioral_correlation',
                'file': obfuscation[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{obfuscation[0]["name"]} + {network[0]["name"]}',
                'confidence': 'MEDIUM',
                'attack_type': 'stealth_backdoor'
            })

        # 7. Clipboard + crypto patterns = potential wallet hijacking
        clipboard = [f for f in all_findings if 'clipboard' in f.get('name', '').lower()]
        crypto = categories.get('weak_crypto', []) + [
            f for f in all_findings
            if any(k in f.get('evidence', '') for k in ['0x', 'wallet', 'ethereum', 'bitcoin'])
        ]
        if clipboard and crypto:
            correlations.append({
                'name': 'Potential wallet hijacking: clipboard access + crypto patterns',
                'severity': 'critical',
                'description': 'Extension accesses clipboard and contains crypto patterns - possible address swap capability',
                'category': 'behavioral_correlation',
                'file': clipboard[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{clipboard[0]["name"]} + crypto pattern',
                'confidence': 'MEDIUM',
                'attack_type': 'wallet_hijacking'
            })

        # 8. Real-time document monitoring + network = potential data collection
        doc_change_listeners = categories.get('document_monitoring', [])
        network_exfil = categories.get('network_exfil', []) + categories.get('insecure_endpoint', [])
        # Only trigger if we have doc monitoring AND network AND haven't already flagged in rule 1
        if doc_change_listeners and network_exfil and not (doc_monitoring and base64_exfil and network):
            correlations.append({
                'name': 'Real-time document monitoring + network transmission',
                'severity': 'critical',
                'description': 'Extension monitors document changes in real-time AND sends network requests - '
                               'review what data is collected and where it is sent',
                'category': 'behavioral_correlation',
                'file': doc_change_listeners[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{doc_change_listeners[0]["name"]} + {network_exfil[0]["name"]}',
                'confidence': 'HIGH',
                'attack_type': 'keylogging'
            })

        # 9. User input source (QuickPick/InputBox) + shell execution in same file
        cmd_injection = categories.get('command_injection', [])
        if cmd_injection:
            # Check if any command injection finding is in a file that also uses QuickPick/InputBox
            cmd_files = {f.get('file') for f in cmd_injection}
            input_source_files = set()
            for f in all_findings:
                if f.get('category') == 'workspace_activity_monitoring' or \
                   'QuickPick' in f.get('evidence', '') or \
                   'InputBox' in f.get('evidence', ''):
                    input_source_files.add(f.get('file'))
            # Also scan raw evidence for QuickPick/InputBox across all findings
            for f in all_findings:
                evidence = f.get('evidence', '')
                if any(k in evidence for k in ['showQuickPick', 'showInputBox',
                                                'onDidChangeValue', 'onDidAccept']):
                    input_source_files.add(f.get('file'))
            overlap = cmd_files & input_source_files
            if overlap:
                correlations.append({
                    'name': 'Shell execution with user-controlled input (same file)',
                    'severity': 'medium',
                    'description': 'User input source (QuickPick/InputBox) and shell command execution '
                                   'exist in the same file - user input may reach shell commands. '
                                   'Review whether input is properly sanitized.',
                    'category': 'behavioral_correlation',
                    'file': list(overlap)[0],
                    'line': 0,
                    'evidence': f'User input + shell execution co-located in: {", ".join(overlap)}',
                    'confidence': 'MEDIUM',
                    'attack_type': 'user_input_shell_injection'
                })

        # 10. Workspace activity monitoring + process execution (no network) = local tool integration
        workspace_activity = categories.get('workspace_activity_monitoring', [])
        if workspace_activity and proc_exec and not network:
            correlations.append({
                'name': 'Local tool integration: workspace monitoring + command execution (no network)',
                'severity': 'low',
                'description': 'Extension monitors workspace activity and executes commands but has '
                               'NO network access. Consistent with local CLI tool integration. '
                               'High capability but justified pattern.',
                'category': 'behavioral_correlation',
                'file': workspace_activity[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{workspace_activity[0]["name"]} + {proc_exec[0]["name"]} + no network',
                'confidence': 'HIGH',
                'attack_type': 'local_tool_integration'
            })

        # 11. Staged payload: network fetch + code execution (eval/Function) = remote code loader
        # Detects benign-looking extensions that fetch remote content and execute it
        code_exec = categories.get('code_execution', [])
        if network and code_exec:
            # Look specifically for indirect eval patterns combined with network fetch
            indirect_eval_names = [
                'indirect eval', 'function() constructor', 'constructor chain',
                'reflect.construct', 'dynamic import', 'vm.compilefunction',
                'bracket notation eval'
            ]
            has_indirect_eval = any(
                any(ie in f.get('name', '').lower() for ie in indirect_eval_names)
                for f in code_exec
            )
            # Also detect: few total findings (benign-looking loader) OR explicit fetch+eval
            fetch_patterns = [f for f in network if any(
                k in f.get('name', '').lower()
                for k in ['https', 'fetch', 'get', 'request', 'http', 'ip-based',
                           'socket', 'webhook', 'telegram', 'discord', 'endpoint']
            )]
            if has_indirect_eval and fetch_patterns:
                correlations.append({
                    'name': 'Staged payload loader: network fetch + indirect code execution',
                    'severity': 'critical',
                    'description': 'Extension fetches remote content and executes it via indirect eval/'
                                   'Function/constructor chain. This is the hallmark of a staged payload '
                                   'loader - the extension code appears benign but loads and runs '
                                   'arbitrary remote code at runtime.',
                    'category': 'behavioral_correlation',
                    'file': code_exec[0].get('file', 'unknown'),
                    'line': 0,
                    'evidence': f'{fetch_patterns[0]["name"]} + {code_exec[0]["name"]}',
                    'confidence': 'HIGH',
                    'attack_type': 'staged_payload'
                })

        # 12. VSCode API abuse: auth token theft + network = credential exfiltration
        auth_theft = [f for f in all_findings if f.get('attack_type') == 'auth_token_theft'
                      or 'authentication.getSession' in f.get('evidence', '')]
        if auth_theft and network:
            correlations.append({
                'name': 'OAuth token theft: VSCode auth API + network exfiltration',
                'severity': 'critical',
                'description': 'Extension accesses VSCode authentication sessions (GitHub/Microsoft tokens) '
                               'and has network capabilities - potential OAuth token exfiltration.',
                'category': 'behavioral_correlation',
                'file': auth_theft[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{auth_theft[0]["name"]} + {network[0]["name"]}',
                'confidence': 'HIGH',
                'attack_type': 'oauth_token_theft'
            })

        # 13. Task/terminal-based execution (no child_process) = evasive command execution
        task_exec = [f for f in all_findings if any(
            k in f.get('name', '').lower()
            for k in ['shellexecution', 'tasks.executetask', 'terminal.sendsequence',
                       'registertaskprovider']
        )]
        # Check specifically for child_process-based exec (not Tasks API findings)
        child_process_exec = [f for f in all_findings if any(
            k in f.get('evidence', '').lower()
            for k in ['child_process', 'require(\'child_process', 'require("child_process',
                       'execsync', 'spawnsync', 'execfilesync']
        ) and f.get('category') in ('command_injection', 'code_execution')]
        if task_exec and not child_process_exec:
            correlations.append({
                'name': 'Evasive command execution via VSCode Tasks/Terminal API',
                'severity': 'high',
                'description': 'Extension executes commands via VSCode Tasks API or terminal.sendSequence '
                               'instead of child_process - an evasion technique to avoid standard '
                               'command execution detection.',
                'category': 'behavioral_correlation',
                'file': task_exec[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{task_exec[0]["name"]} (no child_process imports detected)',
                'confidence': 'HIGH',
                'attack_type': 'evasive_execution'
            })

        # 14. Persistence + network = C2 configuration storage
        persistence = categories.get('persistence', [])
        if persistence and network and len(persistence) >= 3:
            correlations.append({
                'name': 'C2 persistence: extensive state storage + network exfiltration',
                'severity': 'high',
                'description': 'Extension uses persistent storage (globalState/workspaceState) extensively '
                               'combined with network access - pattern consistent with C2 configuration '
                               'persistence and payload staging.',
                'category': 'behavioral_correlation',
                'file': persistence[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{len(persistence)} persistence ops + {network[0]["name"]}',
                'confidence': 'HIGH',
                'attack_type': 'c2_persistence'
            })

        # 15. Telemetry/fingerprinting + network = device fingerprint exfiltration
        telemetry = categories.get('telemetry_abuse', [])
        recon = categories.get('reconnaissance', [])
        if telemetry and network and (len(telemetry) >= 2 or (telemetry and recon)):
            correlations.append({
                'name': 'Device fingerprinting + exfiltration: hardware/environment profiling + network',
                'severity': 'high',
                'description': 'Extension collects device hardware information (CPU, memory, network interfaces) '
                               'and/or environment variables combined with network access - potential device '
                               'fingerprinting and environment reconnaissance exfiltration.',
                'category': 'behavioral_correlation',
                'file': telemetry[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{telemetry[0]["name"]} + {network[0]["name"]}',
                'confidence': 'HIGH',
                'attack_type': 'fingerprint_exfil'
            })

        # 16. Multiple distinct network exfil methods = multi-channel C2
        network_exfil_only = categories.get('network_exfil', [])
        distinct_methods = set()
        for f in network_exfil_only:
            name = f.get('name', '').lower()
            if 'discord' in name: distinct_methods.add('discord')
            elif 'telegram' in name: distinct_methods.add('telegram')
            elif 'pastebin' in name or 'gist' in name: distinct_methods.add('pastebin')
            elif 'socket' in name: distinct_methods.add('socket')
            elif 'https' in name and 'get' in name: distinct_methods.add('https_get')
            elif 'http' in name and 'post' in name: distinct_methods.add('http_post')
            elif 'webhook' in name: distinct_methods.add('webhook')
            elif 'ip-based' in name: distinct_methods.add('ip_direct')
        if len(distinct_methods) >= 3:
            correlations.append({
                'name': f'Multi-channel C2: {len(distinct_methods)} distinct exfiltration methods',
                'severity': 'critical',
                'description': f'Extension uses {len(distinct_methods)} different network exfiltration channels '
                               f'({", ".join(sorted(distinct_methods))}). Multiple redundant exfil methods '
                               f'indicate a sophisticated C2 infrastructure with fallback channels.',
                'category': 'behavioral_correlation',
                'file': network_exfil_only[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'Channels: {", ".join(sorted(distinct_methods))}',
                'confidence': 'HIGH',
                'attack_type': 'multi_channel_c2'
            })

        # 17. Credential theft + network = credential exfiltration
        cred_theft = categories.get('credential_theft', [])
        file_harvest = categories.get('workspace_harvesting', [])
        if cred_theft and network and file_harvest:
            correlations.append({
                'name': 'Credential harvesting + exfiltration: file theft + credential paths + network',
                'severity': 'critical',
                'description': 'Extension accesses credential files (SSH keys, tokens, passwords) via '
                               'file system APIs and has network exfiltration capability - consistent '
                               'with credential theft and exfiltration malware.',
                'category': 'behavioral_correlation',
                'file': cred_theft[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{cred_theft[0]["name"]} + {file_harvest[0]["name"]} + {network[0]["name"]}',
                'confidence': 'HIGH',
                'attack_type': 'credential_exfiltration'
            })

        # ══════════════════════════════════════════════════════════════════
        # V2 Capability-based behavioral correlations
        # These detect compound attack patterns from capability stacks
        # ══════════════════════════════════════════════════════════════════

        local_server = categories.get('local_server', [])
        clipboard = categories.get('clipboard_access', [])
        identity = categories.get('identity_harvesting', [])
        remote_orch = categories.get('remote_orchestration', [])
        terminal_hijack = categories.get('terminal_hijack', [])

        # 18. Remote Automation Agent: shell exec + network + local server/remote orchestration
        if proc_exec and network and (local_server or remote_orch):
            evidence_parts = [proc_exec[0]['name']]
            if local_server:
                evidence_parts.append(local_server[0]['name'])
            if remote_orch:
                evidence_parts.append(remote_orch[0]['name'])
            evidence_parts.append(network[0]['name'])

            correlations.append({
                'name': 'Remote Automation Agent: shell exec + local server + remote orchestration',
                'severity': 'critical',
                'description': 'Extension can execute shell commands AND runs a local server or '
                               'communicates with a remote orchestration backend. This is the '
                               'architecture of a remote automation agent - the machine becomes '
                               'a worker node controlled by an external server.',
                'category': 'behavioral_correlation',
                'file': proc_exec[0].get('file', 'unknown'),
                'line': 0,
                'evidence': ' + '.join(evidence_parts),
                'confidence': 'HIGH',
                'attack_type': 'remote_agent'
            })

        # 19. Stealth Command Execution: shell exec + hidden terminal
        hidden_terminal = [f for f in all_findings if 'hideFromUser' in f.get('name', '').lower()
                          or 'hidden terminal' in f.get('name', '').lower()]
        if proc_exec and hidden_terminal:
            correlations.append({
                'name': 'Stealth command execution: shell exec + hidden terminal',
                'severity': 'critical',
                'description': 'Extension executes shell commands AND creates terminals hidden '
                               'from the user. Commands run without user awareness or consent.',
                'category': 'behavioral_correlation',
                'file': hidden_terminal[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{proc_exec[0]["name"]} + {hidden_terminal[0]["name"]}',
                'confidence': 'HIGH',
                'attack_type': 'stealth_execution'
            })

        # 20. Clipboard Surveillance: clipboard read + write (+ optional network)
        clip_read = [f for f in clipboard if 'read' in f.get('name', '').lower()]
        clip_write = [f for f in clipboard if 'write' in f.get('name', '').lower()]
        if clip_read and clip_write:
            correlations.append({
                'name': 'Clipboard surveillance: read + write access',
                'severity': 'high',
                'description': 'Extension can both read and write clipboard content. '
                               'This enables clipboard interception (reading sensitive '
                               'data like passwords, crypto addresses) and clipboard '
                               'injection (replacing content with malicious data).',
                'category': 'behavioral_correlation',
                'file': clip_read[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{clip_read[0]["name"]} + {clip_write[0]["name"]}',
                'confidence': 'HIGH',
                'attack_type': 'clipboard_surveillance'
            })
        elif clipboard and network:
            correlations.append({
                'name': 'Clipboard access + network: potential clipboard exfiltration',
                'severity': 'high',
                'description': 'Extension accesses clipboard and has network capabilities - '
                               'clipboard content may be sent to external servers.',
                'category': 'behavioral_correlation',
                'file': clipboard[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{clipboard[0]["name"]} + {network[0]["name"]}',
                'confidence': 'MEDIUM',
                'attack_type': 'clipboard_exfil'
            })

        # 21. Identity Harvesting: GitHub/OAuth identity + network
        if identity and network:
            correlations.append({
                'name': 'Identity harvesting: user identity collection + network exfiltration',
                'severity': 'critical',
                'description': 'Extension collects user identity (GitHub account, email, '
                               'OAuth tokens) and has network access. User identity may '
                               'be exfiltrated for account linking, tracking, or impersonation.',
                'category': 'behavioral_correlation',
                'file': identity[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{identity[0]["name"]} + {network[0]["name"]}',
                'confidence': 'HIGH',
                'attack_type': 'identity_harvesting'
            })

        # 22. Remote Control Channel: local server + remote domain (no shell exec)
        if local_server and network and not proc_exec:
            correlations.append({
                'name': 'Remote control channel: local server + external communication',
                'severity': 'high',
                'description': 'Extension runs a local server and communicates with '
                               'external endpoints - potential remote control channel '
                               'or tunneling architecture.',
                'category': 'behavioral_correlation',
                'file': local_server[0].get('file', 'unknown'),
                'line': 0,
                'evidence': f'{local_server[0]["name"]} + {network[0]["name"]}',
                'confidence': 'MEDIUM',
                'attack_type': 'remote_control'
            })

        return correlations

    # ──────────────────────────────────────────────────────────────────────
    # False positive filtering for VSCode extensions
    # ──────────────────────────────────────────────────────────────────────
    def _filter_vscode_false_positives(self, findings, extension_dir):
        """Filter out known false positives from library code in VSCode extensions"""
        filtered = []
        suppressed = []
        # Cache file size per path to avoid repeated stat() when many findings in same file
        _file_size_cache = {}

        for finding in findings:
            file_path = finding.get('file', '')
            file_name = Path(file_path).name.lower()
            category = finding.get('category', '')
            evidence = finding.get('evidence', '')

            # Rule 1: Suppress library-generated findings
            if file_name in self.KNOWN_LIBRARY_FILES and category in self.LIBRARY_SUPPRESSIBLE_CATEGORIES:
                suppressed.append({'finding': finding['name'], 'reason': f'Known library: {file_name}'})
                continue

            # Rule 2: Suppress Unicode regex character classes flagged as obfuscation
            if category == 'obfuscation' and finding['name'] == 'Unicode escape sequences':
                if re.search(r'\[.*\\u[0-9a-fA-F]{4}.*\]', evidence):
                    suppressed.append({'finding': finding['name'], 'reason': 'Unicode regex char class'})
                    continue

            # Rule 3: Suppress base64 alphabet constants
            if category == 'obfuscation' and finding['name'] == 'Base64 encoded blocks':
                if 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' in evidence:
                    suppressed.append({'finding': finding['name'], 'reason': 'Base64 alphabet constant'})
                    continue

            # Rule 4: Suppress __proto__ in polyfill contexts (setPrototypeOf fallback)
            if category == 'prototype_pollution' and finding['name'] == '__proto__ assignment':
                if any(p in evidence for p in ['setPrototypeOf', 'Object.create', '||function']):
                    suppressed.append({'finding': finding['name'], 'reason': 'Polyfill __proto__ fallback'})
                    continue

            # Rule 5: Suppress innerHTML in well-known framework files or dependency code
            if finding['name'] == 'Webview innerHTML assignment':
                if any(fw in file_name for fw in ['vue', 'react', 'angular', 'svelte', 'lit',
                                                   'highlight', 'prism', 'codemirror', 'katex']):
                    suppressed.append({'finding': finding['name'], 'reason': f'Framework: {file_name}'})
                    continue
                if finding.get('path_type') == 'dependency':
                    suppressed.append({'finding': finding['name'], 'reason': 'Dependency/third-party code'})
                    continue

            # Rule 5b: Suppress "Bulk file reading" when evidence is HTTPS server cert/key (legitimate)
            if category == 'workspace_harvesting' and finding.get('name') == 'Bulk file reading with variable path':
                ev_lower = (evidence or '').lower()
                if any(x in ev_lower for x in ['cert', 'key', 'ssl', 'https', '.pem', 'tls', 'httpsconfig']):
                    suppressed.append({'finding': finding['name'], 'reason': 'HTTPS server cert/key read (legitimate)'})
                    continue

            # Rule 5c: Suppress localhost HTTP when benign (Bablu review: eamodio.gitlens, GitHub.copilot-chat)
            if category == 'localhost_access' and finding.get('name') == 'Localhost HTTP access from extension code':
                ev = (evidence or '')
                if ':11434' in ev or 'localhost:11434' in ev:
                    suppressed.append({'finding': finding['name'], 'reason': 'Ollama local LLM endpoint (localhost:11434)'})
                    continue
                if ':4318' in ev or 'localhost:4318' in ev:
                    suppressed.append({'finding': finding['name'], 'reason': 'OpenTelemetry exporter (localhost:4318)'})
                    continue
                if 'new URL(' in ev and 'http://localhost' in ev and ev.count('http://localhost') == 1:
                    suppressed.append({'finding': finding['name'], 'reason': 'Base URL for URL() constructor only, no fetch'})
                    continue

            # Rule 6: Suppress low-severity findings in large minified files (>500KB)
            if finding.get('severity') == 'low':
                try:
                    size = _file_size_cache.get(file_path)
                    if size is None:
                        full_path = Path(extension_dir) / file_path
                        _file_size_cache[file_path] = full_path.stat().st_size if full_path.exists() else 0
                        size = _file_size_cache[file_path]
                    if size > 500 * 1024:
                        suppressed.append({'finding': finding['name'], 'reason': 'Low severity in large minified file'})
                        continue
                except Exception:
                    pass

            # Rule 7: Downgrade all dependency-path findings (not app code)
            # Keep them in data for completeness but flag them and lower severity
            # so they don't inflate headline counts or alarm analysts.
            if finding.get('path_type') == 'dependency':
                sev = finding.get('severity', 'medium')
                if sev in ('critical', 'high'):
                    finding['severity'] = 'low'
                elif sev == 'medium':
                    finding['severity'] = 'info'
                finding['dependency_suppressed'] = True
                finding['original_severity'] = sev

            filtered.append(finding)

        return filtered, suppressed

    # ──────────────────────────────────────────────────────────────────────
    # Typosquatting detection
    # ──────────────────────────────────────────────────────────────────────
    def _check_typosquatting(self, dep_name):
        """Check if a dependency name looks like a typosquat of a popular package"""
        if dep_name in self.POPULAR_PACKAGES or dep_name in self.TYPOSQUAT_WHITELIST:
            return None

        for popular in self.POPULAR_PACKAGES:
            distance = self._levenshtein_distance(dep_name, popular)
            if 0 < distance <= 2 and len(dep_name) >= 3:
                return {
                    'type': 'potential_typosquat',
                    'severity': 'high',
                    'package': dep_name,
                    'similar_to': popular,
                    'edit_distance': distance,
                    'detail': f'"{dep_name}" is suspiciously similar to "{popular}" (edit distance: {distance})'
                }

        # Scope-squatting: @malicious/lodash
        if dep_name.startswith('@') and '/' in dep_name:
            bare_name = dep_name.split('/')[-1]
            if bare_name in self.POPULAR_PACKAGES:
                return {
                    'type': 'potential_scope_squat',
                    'severity': 'medium',
                    'package': dep_name,
                    'similar_to': bare_name,
                    'detail': f'Scoped package "{dep_name}" wraps popular name "{bare_name}" - verify publisher'
                }

        return None

    @staticmethod
    def _levenshtein_distance(s1, s2):
        """Compute Levenshtein edit distance between two strings"""
        if len(s1) < len(s2):
            return VSCodeStaticAnalyzer._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                curr_row.append(min(prev_row[j + 1] + 1, curr_row[j] + 1, prev_row[j] + (c1 != c2)))
            prev_row = curr_row
        return prev_row[-1]

    def _walk_skip_node_modules(self, root_dir, extensions):
        """Walk directory tree skipping node_modules entirely (os.walk is faster than rglob)"""
        result = []
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Prune node_modules from the walk so os.walk never enters it
            dirnames[:] = [d for d in dirnames if d != 'node_modules']
            for fname in filenames:
                if Path(fname).suffix.lower() in extensions:
                    result.append(Path(dirpath) / fname)
        return result

    def _resolve_nls(self, pkg, extension_dir):
        """Resolve %placeholder% values from package.nls.json (VSCode i18n)."""
        nls = {}
        for nls_file in ('package.nls.json', 'package.nls.en.json'):
            nls_path = Path(extension_dir) / nls_file
            if nls_path.is_file():
                try:
                    nls = json.loads(nls_path.read_text(encoding='utf-8', errors='replace'))
                    break
                except Exception:
                    pass
        if not nls:
            return
        import re as _re
        placeholder_re = _re.compile(r'^%(.+)%$')
        for key in ('displayName', 'description'):
            val = pkg.get(key, '')
            if isinstance(val, str):
                m = placeholder_re.match(val)
                if m and m.group(1) in nls:
                    pkg[key] = nls[m.group(1)]

    def _read_package_json(self, extension_dir):
        """Read package.json from extension directory"""
        pkg_path = extension_dir / 'package.json'
        if not pkg_path.exists():
            print(f"[!] package.json not found in {extension_dir}")
            return None
        try:
            with open(pkg_path, 'r', encoding='utf-8', errors='ignore') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"[!] Invalid package.json: {e}")
            return None

    def _read_file(self, file_path, max_bytes=None):
        """Read file with caching. If max_bytes is set, read only the first max_bytes (for large files)."""
        file_path = str(file_path)
        cache_key = (file_path, max_bytes)
        if cache_key not in self._file_cache:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    if max_bytes is not None:
                        self._file_cache[cache_key] = f.read(max_bytes)
                    else:
                        self._file_cache[cache_key] = f.read()
            except Exception:
                self._file_cache[cache_key] = None
        return self._file_cache[cache_key]

    def update_risk_with_virustotal(self, results, vt_results):
        """Update risk score based on VirusTotal findings"""
        malicious = [r for r in vt_results if r.get('threat_level') == 'MALICIOUS']
        suspicious = [r for r in vt_results if r.get('threat_level') == 'SUSPICIOUS']

        if malicious:
            results['risk_score'] = min(10.0, results['risk_score'] + 3.0)
            if results['risk_level'] not in ['CRITICAL']:
                results['risk_level'] = 'CRITICAL'
        elif suspicious:
            results['risk_score'] = min(10.0, results['risk_score'] + 1.0)

        results['virustotal_results'] = vt_results
        return results

    def save_report(self, results, output_dir='reports'):
        """Save JSON report"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        identifier = results.get('identifier', 'unknown')
        safe_name = re.sub(r'[^\w\-.]', '_', identifier)
        report_path = output_dir / f"vscode_{safe_name}_analysis.json"

        # Clean results for JSON serialization
        clean = self._make_serializable(results)

        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(clean, f, indent=2, default=str)

        return report_path

    def _make_serializable(self, obj):
        """Make object JSON-serializable"""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(v) for v in obj]
        elif isinstance(obj, Path):
            return str(obj)
        elif isinstance(obj, set):
            return list(obj)
        else:
            return obj
