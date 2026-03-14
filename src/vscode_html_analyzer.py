"""
VSCode HTML/Webview Analyzer - Detects hidden iframes, analytics injection, and XSS patterns

Validated against the ChatMoss malware (zhukunpeng.chat-moss) which uses:
  - Zero-pixel hidden iframe to C2 domain (chatmoss-shuju.aihao123.cn)
  - CSS-based iframe hiding (width: 0px; height: 0px in <style> block)
  - Chinese analytics SDK injection via hidden iframe
"""

import os
import re
from pathlib import Path


class VSCodeHTMLAnalyzer:
    """Analyzes HTML/webview files in VSCode extensions for security threats"""

    # ── Hidden iframe detection ──────────────────────────────────────────
    HIDDEN_IFRAME_PATTERNS = [
        {
            'name': 'Hidden iframe (zero-pixel inline dimensions)',
            'pattern': re.compile(
                r'<iframe[^>]*(?:width\s*=\s*["\']?\s*0|height\s*=\s*["\']?\s*0)[^>]*>',
                re.IGNORECASE | re.DOTALL
            ),
            'severity': 'critical',
            'description': 'Zero-pixel iframe - hidden C2/tracking channel (ChatMoss pattern)',
            'category': 'hidden_iframe'
        },
        {
            'name': 'Hidden iframe (CSS display:none or visibility:hidden)',
            'pattern': re.compile(
                r'<iframe[^>]*style\s*=\s*["\'][^"\']*'
                r'(?:display\s*:\s*none|visibility\s*:\s*hidden)[^"\']*["\'][^>]*>',
                re.IGNORECASE | re.DOTALL
            ),
            'severity': 'critical',
            'description': 'Hidden iframe via inline CSS - invisible tracking/C2 channel',
            'category': 'hidden_iframe'
        },
        {
            'name': 'Iframe loading plaintext HTTP URL',
            'pattern': re.compile(
                r'<iframe[^>]*src\s*=\s*["\']http://(?!localhost|127\.0\.0\.1)[^"\']+["\'][^>]*>',
                re.IGNORECASE
            ),
            'severity': 'high',
            'description': 'Iframe loads plaintext HTTP URL - insecure C2 channel',
            'category': 'hidden_iframe'
        },
        {
            'name': 'Iframe loading external domain',
            'pattern': re.compile(
                r'<iframe[^>]*src\s*=\s*["\']https?://[^"\']+["\'][^>]*>',
                re.IGNORECASE
            ),
            'severity': 'medium',
            'description': 'Iframe loads external URL - potential data exfiltration channel',
            'category': 'hidden_iframe'
        },
    ]

    # ── Analytics / tracking injection ───────────────────────────────────
    ANALYTICS_INJECTION_PATTERNS = [
        {
            'name': 'Chinese analytics SDK script tag',
            'pattern': re.compile(
                r'<script[^>]*src\s*=\s*["\'][^"\']*'
                r'(?:zhuge\.io|growingio\.com|talkingdata\.com|hm\.baidu\.com|'
                r'cnzz\.com|51\.la|umeng\.com)[^"\']*["\']',
                re.IGNORECASE
            ),
            'severity': 'high',
            'description': 'Chinese analytics/tracking SDK injected via script tag',
            'category': 'analytics_injection'
        },
        {
            'name': 'Tracking pixel image (1x1 or 0x0)',
            'pattern': re.compile(
                r'<img[^>]*(?:width\s*=\s*["\']?[01]\b|height\s*=\s*["\']?[01]\b)[^>]*'
                r'src\s*=\s*["\']https?://[^"\']+',
                re.IGNORECASE
            ),
            'severity': 'medium',
            'description': 'Tracking pixel detected - invisible image for user tracking',
            'category': 'analytics_injection'
        },
        {
            'name': 'Generic analytics SDK reference',
            'pattern': re.compile(
                r'(?:zhuge|growingio|talkingdata|baiduAnalytics|hm\.baidu)',
                re.IGNORECASE
            ),
            'severity': 'high',
            'description': 'Analytics/fingerprinting SDK reference in HTML',
            'category': 'analytics_injection'
        },
    ]

    # ── Webview XSS patterns ─────────────────────────────────────────────
    WEBVIEW_XSS_PATTERNS = [
        {
            'name': 'External script from non-CDN origin',
            'pattern': re.compile(
                r'<script[^>]*src\s*=\s*["\']https?://(?!cdn\.jsdelivr\.net|'
                r'cdnjs\.cloudflare\.com|unpkg\.com|code\.jquery\.com)[^"\']+["\']',
                re.IGNORECASE
            ),
            'severity': 'medium',
            'description': 'External script loaded from non-CDN origin in webview',
            'category': 'webview_xss'
        },
        {
            'name': 'command: URI link in webview',
            'pattern': re.compile(
                r'href\s*=\s*["\']command:[^"\']+["\']',
                re.IGNORECASE
            ),
            'severity': 'high',
            'description': 'Anchor/link uses VS Code command: URI inside webview/HTML - can trigger arbitrary commands from rendered content',
            'category': 'webview_risk'
        },
    ]

    # CSS patterns that hide iframes (separate from inline attributes)
    CSS_IFRAME_HIDE_PATTERN = re.compile(
        r'(?:iframe|\.hidden-frame|#tracking)\s*\{[^}]*'
        r'(?:width\s*:\s*0|height\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden)'
        r'[^}]*\}',
        re.IGNORECASE | re.DOTALL
    )

    IFRAME_TAG_PATTERN = re.compile(r'<iframe\b', re.IGNORECASE)
    IFRAME_SRC_PATTERN = re.compile(
        r'<iframe[^>]*src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE
    )

    def __init__(self):
        self.all_patterns = (
            self.HIDDEN_IFRAME_PATTERNS +
            self.ANALYTICS_INJECTION_PATTERNS +
            self.WEBVIEW_XSS_PATTERNS
        )

    def analyze_html_files(self, extension_dir):
        """
        Scan all HTML/HTM files in the extension for webview-based attacks.

        Args:
            extension_dir: Path to extracted extension directory

        Returns:
            dict: {findings: [...], files_scanned: int, iframe_urls: [...]}
        """
        extension_dir = Path(extension_dir)
        findings = []
        iframe_urls = []
        files_scanned = 0

        html_extensions = {'.html', '.htm'}

        for dirpath, dirnames, filenames in os.walk(extension_dir):
            dirnames[:] = [d for d in dirnames if d != 'node_modules']
            for fname in filenames:
                if Path(fname).suffix.lower() in html_extensions:
                    fpath = Path(dirpath) / fname
                    files_scanned += 1
                    try:
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        relative = str(fpath.relative_to(extension_dir))

                        # Run all pattern scans
                        for pattern_def in self.all_patterns:
                            for match in pattern_def['pattern'].finditer(content):
                                line_num = content[:match.start()].count('\n') + 1
                                start = max(0, match.start() - 40)
                                end = min(len(content), match.end() + 40)
                                context = content[start:end].replace('\n', ' ').strip()

                                findings.append({
                                    'name': pattern_def['name'],
                                    'severity': pattern_def['severity'],
                                    'description': pattern_def['description'],
                                    'category': pattern_def['category'],
                                    'file': relative,
                                    'line': line_num,
                                    'evidence': context[:200]
                                })

                        # CSS-based iframe hiding (ChatMoss pattern)
                        css_findings = self._check_iframe_css_hiding(content, relative)
                        findings.extend(css_findings)

                        # Extract iframe URLs for domain analysis
                        for match in self.IFRAME_SRC_PATTERN.finditer(content):
                            iframe_urls.append({
                                'url': match.group(1),
                                'file': relative,
                                'line': content[:match.start()].count('\n') + 1
                            })

                    except Exception:
                        continue

        return {
            'findings': findings,
            'files_scanned': files_scanned,
            'iframe_urls': iframe_urls
        }

    def _check_iframe_css_hiding(self, html_content, file_path):
        """
        Detect CSS rules that hide iframes via <style> blocks.
        Catches ChatMoss pattern: <style>iframe { width: 0px; height: 0px; }</style>
        """
        findings = []

        for match in self.CSS_IFRAME_HIDE_PATTERN.finditer(html_content):
            # Only flag if there is also an <iframe> tag in the same file
            if self.IFRAME_TAG_PATTERN.search(html_content):
                line_num = html_content[:match.start()].count('\n') + 1
                findings.append({
                    'name': 'CSS-hidden iframe detected',
                    'severity': 'critical',
                    'description': 'CSS rule hides iframe elements + iframe tag present - covert C2/tracking (ChatMoss pattern)',
                    'category': 'hidden_iframe',
                    'file': file_path,
                    'line': line_num,
                    'evidence': match.group(0)[:200]
                })

        return findings
