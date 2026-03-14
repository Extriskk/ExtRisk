# DOM XSS, XSS Evasion, and Sold-Extension Detection (OWASP & Annex)

This document describes detection patterns added from the **OWASP Cheat Sheet Series** (DOM-based XSS, XSS Prevention, XSS Filter Evasion, CSP) and from **Annex Security** research on sold/malicious Chrome extensions (e.g. “Pixel Perfect”–style analysis: remote code load, CSP stripping, code injection via pixels/scripts).

## References

- **DOM Based XSS Prevention Cheat Sheet**  
  https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html  
  Covers: dangerous sinks (innerHTML, outerHTML, document.write, insertAdjacentHTML, setAttribute for event handlers), location/document sources, encoding rules, and safe sinks (textContent).

- **Cross Site Scripting Prevention Cheat Sheet**  
  https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html  
  Covers: output encoding per context (HTML, attribute, JavaScript, CSS, URL), dangerous contexts, safe sinks, framework escape hatches (e.g. dangerouslySetInnerHTML, bypassSecurityTrust*).

- **XSS Filter Evasion Cheat Sheet**  
  https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html  
  Covers: polyglots, fromCharCode, data: URLs, event handlers, encoding tricks.

- **Content Security Policy Cheat Sheet**  
  https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html  
  Covers: script-src unsafe-inline/unsafe-eval risks, strict CSP.

- **Annex Security – Sold extensions / code injection**  
  https://annex.security/blog/pixel-perfect/  
  Approach: analyze extensions for post-sale malicious updates (CSP removal/weakening, remote script load then eval, code hidden in pixels/canvas). Existing patterns in the analyzer (e.g. CSP header removal, importScripts(https:), remote iframe, fetch+eval, getImageData+decode) align with this.

## New patterns in `static_analyzer.py`

### DOM XSS (OWASP DOM / XSS Prevention)

| Pattern name | Description |
|--------------|-------------|
| **DOM XSS: Location to document.write** | `location.hash` / `location.search` / `document.URL` / `document.baseURI` (or decoded) flows into `document.write` / `document.writeln`. Classic DOM XSS source→sink. |
| **DOM XSS: Location to innerHTML/outerHTML** | Same untrusted location/URL sources assigned to `innerHTML` or `outerHTML`. Use textContent or safe encoding instead. |
| **DOM XSS: insertAdjacentHTML with variable** | `insertAdjacentHTML(position, variable)` with variable content. Prefer insertAdjacentText or sanitized HTML. |
| **DOM XSS: outerHTML assignment with variable** | `element.outerHTML = variable` or `+=`. Dangerous sink if content is untrusted. |
| **Framework XSS escape hatch** | `dangerouslySetInnerHTML`, `bypassSecurityTrustAsHtml`/`AsUrl`/`AsResourceUrl`/`AsScript`, `unsafeHTML`, `htmlLiteral`. Only safe with sanitized input. |
| **javascript: URL with variable (XSS vector)** | `href`/`src` set to `javascript:` + variable or dynamic `javascript:` assignment. Avoid with user/remote data. |
| **DOM XSS: location.hash/search to eval or Function** | Untrusted `location.hash` or `location.search` (or decoded) flows into `eval(...)` or `new Function(...)`. Critical. |

### Annex-style sold extension / remote code load

| Pattern name | Description |
|--------------|-------------|
| **Remote script load then eval/Function (Annex-style)** | Fetch remote URL (e.g. `fetch(url).then(r=>r.text())`) then `eval` / `new Function` / `.innerHTML =`, or eval/Function that receives result of fetch. Enables RCE without store update. |
| **Weakened CSP in manifest (unsafe-inline / unsafe-eval)** | Manifest `content_security_policy` with `unsafe-inline` or `unsafe-eval` (or overly broad script-src). Common after extension sale to allow injected scripts. |

### XSS filter evasion (OWASP)

| Pattern name | Description |
|--------------|-------------|
| **String.fromCharCode to eval/document.write** | `String.fromCharCode(...)` used to build a string that is then passed to `eval`, `document.write`, or `.innerHTML =`. Payload hidden in character codes. |
| **data: URL in script/iframe src (XSS vector)** | `script.src` or `iframe.src` or `href` set to `data:text/html` or `data:text/javascript` (or script element with data: src). Can execute inline payloads. |

## Existing related patterns

- **Document Write Injection** – `document.write` / `document.writeln` (any use).
- **innerHTML Script Injection** – innerHTML assignment containing `<script`.
- **DOM Event Handler Injection** – `setAttribute('onclick', ...)` etc.
- **CSP Header Removal** / **CSP Meta Tag Removal** – removal of CSP (declarativeNetRequest or DOM).
- **Service Worker importScripts** with `https:` – remote script load in worker.
- **Remote Script Injection (createElement)** – `createElement('script')` then `.src =` (remote or variable).
- **Image Data Extraction** / **Canvas Hidden Data** – getImageData + charCodeAt/fromCharCode/decode/eval (steganography / pixel payload).

## Bablu / review notes

- **DOM XSS:** When verifying, confirm the **source** is actually user-controllable (e.g. `location.hash` on a page that can be linked with `#...`) and the **sink** receives that value without encoding. Static pattern may flag defensive or test code.
- **Framework escape hatches:** Legitimate use exists when the value is from a trusted template or sanitized (e.g. DOMPurify). Note “FP: value is sanitized/trusted” if so.
- **Weakened CSP:** MV2 extensions often used `unsafe-inline` for legacy reasons; MV3 prefers no unsafe-inline. Treat as one signal among others.
- **Remote script load + eval:** High confidence for malicious use when the fetch URL is external or variable and the result is executed as code. False positives: bundlers or dev tooling that load then eval in dev-only paths.
