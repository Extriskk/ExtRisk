# Testing the Bablu Skill

## Quick Test

To verify the bablu skill is working, try this in Cursor:

### Test 1: Simple Activation
**Message to AI:**
```
bablu help me understand this project
```

**Expected Response:**
The AI should acknowledge it's working with the Chrome Extension Security Analyzer and explain the project structure, mentioning:
- downloads/ directory for .crx files
- extensions/ directory for unpacked code
- reports/ directory for scan results
- The 150+ malicious pattern detection

---

### Test 2: Check for Existing Scans
**Message to AI:**
```
bablu show me what scans are available
```

**Expected Response:**
The AI should:
1. List files in `reports/` directory
2. Show any existing JSON scan reports
3. Explain what each report contains (if any exist)

---

### Test 3: Scan a Safe Extension (uBlock Origin)
**Step 1: Run a scan**
```bash
cd src
python analyzer.py cjpalhdlnbpafiamejdnhcphjbkeiagm
```

**Step 2: Ask bablu to analyze**
```
bablu analyze the uBlock Origin scan results
```

**Expected Response:**
The AI should:
1. Find the latest report in reports/
2. Read the JSON file
3. Summarize the risk score (should be LOW)
4. Explain that the extension is a legitimate ad blocker
5. Verify any findings are false positives (webRequest permission for ad blocking)

---

### Test 4: Investigate a Specific Pattern
**Message to AI:**
```
bablu explain what cookie theft looks like in JavaScript code
```

**Expected Response:**
The AI should reference PATTERNS.md and explain:
- chrome.cookies.getAll() API
- How stolen cookies get sent via fetch() or XMLHttpRequest
- Example code snippets
- How to distinguish legitimate use from theft

---

### Test 5: Code Verification
First, download and unpack an extension manually, then:

**Message to AI:**
```
bablu read the manifest.json from the latest extension and tell me what permissions it requests
```

**Expected Response:**
The AI should:
1. Find the extension directory in extensions/
2. Read the manifest.json file
3. List all permissions
4. Explain what each permission allows

---

## Advanced Tests

### Test 6: Taint Flow Analysis
**Message to AI:**
```
bablu check if any scan results show data flowing from chrome.cookies to external servers
```

**Expected Response:**
The AI should:
1. Read JSON reports
2. Look for taint_flows field
3. Filter for cookie sources
4. Show any flows to external destinations
5. Assess if the flow is malicious

---

### Test 7: VirusTotal Cross-Check
**Message to AI:**
```
bablu show me any domains that VirusTotal flagged as malicious
```

**Expected Response:**
The AI should:
1. Read virustotal_results from report
2. Filter for threat_level: "MALICIOUS"
3. List flagged domains with vendor counts
4. Suggest investigation steps

---

### Test 8: Compare Multiple Scans
Scan the same extension twice with some time between, then:

**Message to AI:**
```
bablu compare the two most recent scans for extension cjpalhdlnbpafiamejdnhcphjbkeiagm
```

**Expected Response:**
The AI should:
1. Find 2+ reports for that extension
2. Compare risk scores
3. Show new/removed patterns
4. Highlight significant changes

---

## Verification Checklist

After running tests, verify:

- [ ] AI recognizes the word "bablu" as trigger
- [ ] AI mentions the skill name or Chrome Extension Security Analyzer
- [ ] AI can read files from downloads/, extensions/, reports/
- [ ] AI uses correct directory structure
- [ ] AI references PATTERNS.md for threat explanations
- [ ] AI can parse JSON report format correctly
- [ ] AI understands taint flows, VirusTotal results, risk scores

---

## Troubleshooting

### Issue: AI doesn't recognize "bablu"
**Solution:**
- Restart Cursor
- Check that .cursor/skills/bablu/SKILL.md exists
- Verify YAML frontmatter is correct (name: bablu, description: ...)

### Issue: AI can't find reports
**Solution:**
- Confirm reports/ directory exists in project root
- Run a test scan to generate reports: `python src/analyzer.py cjpalhdlnbpafiamejdnhcphjbkeiagm`
- Check file paths in error messages

### Issue: AI gives generic responses
**Solution:**
- Be more specific in your request
- Explicitly mention "scan results" or "extension analysis"
- Reference specific file names or extension IDs

---

## Expected Skill Behavior

**When you say "bablu", the AI should:**
1. ✓ Know it's working with browser extension security analysis
2. ✓ Use the project directory structure (downloads/, extensions/, reports/)
3. ✓ Reference threat patterns from PATTERNS.md
4. ✓ Parse JSON report format correctly
5. ✓ Distinguish false positives from real threats
6. ✓ Explain findings in security research context
7. ✓ Suggest verification steps for suspicious patterns
8. ✓ Cross-reference VirusTotal results with code findings

**The AI should NOT:**
- ✗ Hallucinate report contents (should read actual files)
- ✗ Claim to run scans (only reads existing reports)
- ✗ Make up threat patterns (should reference PATTERNS.md)
- ✗ Ignore context from the skill files

---

## Example Full Workflow

```
You: bablu I need to analyze a suspicious extension

AI: I'll help you analyze a browser extension using the Chrome Extension 
    Security Analyzer. What's the extension ID? (It's the 32-character 
    string from the Chrome Web Store URL)

You: It's nkbihfbeogaeaoehlefnkodbefgpgknn

AI: Let me check if we have existing scan results for this extension...
    [Searches reports/ directory]
    
    I don't see any existing reports. Would you like me to guide you 
    through running a scan?
    
    Run this command:
    cd src
    python analyzer.py nkbihfbeogaeaoehlefnkodbefgpgknn
    
    Then I can analyze the results!

You: [Runs the scan]

You: bablu analyze the results

AI: I'll analyze the scan results for extension nkbihfbeogaeaoehlefnkodbefgpgknn.
    [Reads JSON report]
    
    ANALYSIS RESULTS:
    
    Extension: MetaMask
    Risk Score: 3.2/10 (LOW)
    
    FINDINGS SUMMARY:
    - 2 taint flows detected (data from chrome.storage → fetch)
    - 8 medium-severity patterns (mostly false positives)
    - 0 VirusTotal malicious domains
    
    DETAILED VERIFICATION:
    1. Taint Flow: chrome.storage.local → fetch()
       Location: background.js:145
       Assessment: BENIGN - This is the wallet sync feature
       Destination: metamask.io API (verified safe)
    
    [Continues with more details...]
    
    CONCLUSION: Extension appears safe for use. The detected patterns are 
    consistent with legitimate cryptocurrency wallet functionality.

You: bablu verify the fetch destination

AI: I'll verify the fetch() calls in the actual code...
    [Reads extensions/nkbihfbeogaeaoehlefnkodbefgpgknn/background.js]
    
    Found at line 145:
    ```javascript
    fetch('https://api.metamask.io/v1/sync', {
        method: 'POST',
        body: JSON.stringify(walletState)
    });
    ```
    
    Verification:
    ✓ Domain: api.metamask.io (legitimate)
    ✓ VirusTotal: 0 detections
    ✓ Purpose: Wallet sync (expected functionality)
    ✓ Data: Encrypted wallet state (appropriate)
    
    This is normal behavior for this extension.
```

---

## Success Criteria

The bablu skill is working correctly when:

1. **Recognition:** You say "bablu" and AI immediately understands the context
2. **File Access:** AI reads from correct directories (reports/, extensions/)
3. **Analysis:** AI parses JSON reports and extracts key findings
4. **Verification:** AI cross-checks findings against actual JavaScript code
5. **Explanation:** AI explains threats using PATTERNS.md reference
6. **Context:** AI distinguishes false positives from real threats
7. **Guidance:** AI suggests next steps for investigation

---

**Ready to test!** Start with Test 1 (Simple Activation) and work through the tests.
