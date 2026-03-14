# Debug Hypotheses & Fixes

## Large-Extension Infinite Loop (Resolved)

### H1: calculate_entropy O(256×n)
- **Location:** `static_analyzer.py` `calculate_entropy()`
- **Fix:** Single-pass byte histogram (O(n)); no per-byte full-string scan.

### H2: ReDoS in [\s\S]{0,N} patterns
- **Fix:** Two-pass matching for all N≥50 (was N≥200).

### H3: detect_obfuscation on full 5MB
- **Fix:** Sample first 300 KiB only for obfuscation checks.

### H4: esprima hang on 1–2MB files
- **Fix:** MAX_FILE_SIZE_FOR_AST = 1 MiB.

### H5: Too many JS files
- **Fix:** Cap 300 files; security-prioritized list (manifest + relevance + size).

---

## Other Changes (No Debug Loop)

### Threat attribution false positives
- **Issue:** Pages that only list extensions (e.g. awesome-BrowserRelated) were counted as threat sources.
- **Fix:** Only add to attribution when page has **threat context** (campaign_keywords or proximity match). Dorking searches (extension ID + keyword) ensure the correct resource (e.g. KOI Security) is linked, not benign lists. Infinity (nnnkddnnlpamobajfibfdgfnbcnkgngh) is malicious per KOI and is not in known_benign.

### Report duplicate filenames
- **Issue:** Same basename from different paths (e.g. multiple `background.js`) showed identically.
- **Fix:** `_build_file_display_map()` + `_file_display_name()`; display as `filename`, `filename(2)`, `filename(3)`.

### Scan errors on important files
- **Issue:** user-register.js and similar could error (encoding/parse) and be skipped.
- **Fix:** Multi-encoding read (utf-8, latin-1, cp1252); AST records parse_errors and stub result so file is still counted; manifest-prioritized file list so important files are always in the 300.
