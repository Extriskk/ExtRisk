# Bablu Skill - Quick Reference

## What is Bablu?

Bablu is a Cursor AI skill that helps you analyze JavaScript files from browser extensions and compare them with security scan results. When you say "**bablu**" in Cursor, the AI agent will automatically know to help you with extension analysis tasks.

## How to Use

Just type "**bablu**" in any message to the AI, and it will:
- Understand you want to work with extension analysis
- Help you compare JavaScript code with scan results
- Investigate threat patterns in extension code
- Verify scan findings against actual source files

## What Bablu Can Do

### 1. Compare Code with Scan Results
Say: "bablu check the MetaMask scan results"
- Finds the latest JSON report
- Reads the JavaScript files from the unpacked extension
- Verifies each finding against the actual code
- Tells you if threats are real or false positives

### 2. Investigate Specific Threats
Say: "bablu investigate cookie theft in extension abc123"
- Searches for cookie access patterns
- Traces data flow to network destinations
- Cross-checks with VirusTotal results
- Explains if the pattern is malicious

### 3. Manual Code Review
Say: "bablu review the background.js file"
- Reads the JavaScript file
- Highlights suspicious patterns
- Explains what each section does
- Flags obfuscation or hidden threats

### 4. Version Comparison
Say: "bablu compare scan results from last week"
- Finds multiple scan reports for same extension
- Shows what changed between versions
- Identifies new threats or removed code

## Key Features

**Threat Patterns Covered:**
- Session cookie theft
- Cryptocurrency wallet hijacking
- Keylogging and screen capture
- Phishing via iframe overlays
- Command & control (C2) communication
- Code obfuscation and evasion
- Settings/search engine hijacking
- Steganography (code hidden in images)

**Analysis Capabilities:**
- Taint flow verification (cookies → fetch)
- VirusTotal domain cross-checking
- Obfuscation detection
- False positive filtering
- Campaign attribution matching

## Example Usage

```
You: bablu check the latest uBlock Origin scan

AI: I'll analyze the uBlock Origin extension scan for you.

[Reads report from reports/ directory]
[Locates unpacked extension in extensions/]
[Verifies findings]

Analysis Results:
✓ Risk Score: 2.1/10 (LOW)
✓ No critical threats found
✓ All network requests go to filter list CDNs
✓ 3 medium-severity patterns are false positives (jQuery library)

Verified Findings:
1. "webRequest permission" - BENIGN (needed for ad blocking)
2. "External script load" - BENIGN (filter list updates)
3. "Storage access" - BENIGN (user preferences)

Recommendation: Extension is safe to use.
```

## Project Structure

```
chrome-extension-security-analyzer/
├── .cursor/skills/bablu/     ← The skill files
│   ├── SKILL.md              ← Main skill instructions
│   └── PATTERNS.md           ← Threat pattern reference
├── downloads/                ← Downloaded .crx files
├── extensions/               ← Unpacked extension code
├── reports/                  ← JSON and HTML scan reports
└── src/                      ← Analyzer source code
```

## Quick Commands

**When working with bablu, you can ask:**
- "bablu show me the latest scan reports"
- "bablu verify the cookie theft finding in background.js"
- "bablu what domains are contacted by this extension?"
- "bablu check if this extension steals passwords"
- "bablu deobfuscate this code snippet"
- "bablu compare this week's scan with last month"

## Technical Details

**Report Format:** JSON files in `reports/` directory
**Extension Location:** Unpacked in `extensions/{extension_id}/`
**Key Report Fields:**
- `risk_score` - 0-10 scale
- `malicious_patterns` - Detected threats with file:line
- `taint_flows` - Data flow from sensitive sources to network
- `virustotal_results` - Domain reputation checks
- `ast_results` - JavaScript AST analysis findings

**False Positive Handling:**
Bablu knows about common false positives:
- Firebase backend services
- CDN libraries (jQuery, Bootstrap)
- Legitimate Chrome API usage
- Minified library code

## Advanced Features

**Taint Analysis:**
Bablu can trace data flows like:
```
chrome.cookies.getAll() → JSON.stringify() → fetch(external_url)
        ↑ SOURCE                                     ↑ SINK
```

**Campaign Detection:**
Knows about malware campaigns:
- DarkSpectre (8.8M users affected)
- ChatGPT Mods (16 extensions)
- GhostPoster (steganography)
- ZoomStealer (OAuth theft)

**Obfuscation Analysis:**
Can detect and explain:
- String rotation (reversed strings)
- Base64 encoding
- Constructor chains
- High entropy code

## Tips

1. **Always say "bablu"** at the start so the AI knows to use this skill
2. **Be specific** about what you want to investigate
3. **Ask for verification** if scan findings seem suspicious
4. **Request context** - single lines can be misleading
5. **Check VirusTotal** cross-references for domain reputation

## Next Steps

To use bablu:
1. Run a scan: `python src/analyzer.py <extension_id>`
2. Wait for reports to generate
3. In Cursor, type: "bablu analyze the scan results"
4. The AI will guide you through the findings!

---

**Created:** February 14, 2026
**Version:** 1.0
**Trigger Word:** bablu
