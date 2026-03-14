from __future__ import annotations

"""
Scan service abstraction.

Central place to run a single extension scan (Chrome / Edge / VSCode Market / Open VSX)
and locate the generated reports. API workers and other callers should prefer this
over hand-rolling analyzer invocation and report-path discovery.
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Optional, Dict, Any

from downloader import BrowserType
from analyzer import ChromeExtensionAnalyzer  # type: ignore


class ScanStore(str, Enum):
    CHROME = "chrome"
    EDGE = "edge"
    VSCODE = "vscode"


@dataclass
class ScanRequest:
    extension_id: str
    store: ScanStore
    fast_mode: bool = False


@dataclass
class ScanOutput:
    success: bool
    results: Optional[Dict[str, Any]]
    error: Optional[str]
    extension_dir: str
    json_report_path: str
    html_report_path: str


class ScanService:
    """
    Orchestrates a single scan using ChromeExtensionAnalyzer and finds report paths.

    This is intentionally thin: business logic for DB, jobs, and tenants lives in the
    API layer, but *how* to run a scan and find its reports lives here.
    """

    def __init__(self, reports_dir: Path) -> None:
        self.reports_dir = reports_dir

    def run(
        self,
        request: ScanRequest,
        progress_callback: Optional[Callable[[int, str, str], None]] = None,
    ) -> ScanOutput:
        analyzer = ChromeExtensionAnalyzer()

        # Fast mode: turn off VT/OSINT at the engine level
        if request.fast_mode:
            analyzer.skip_vt = True
            analyzer.skip_osint = True

        # Dispatch based on store
        if request.store == ScanStore.VSCODE:
            results = analyzer.analyze_vscode_extension(request.extension_id)
        else:
            browser_type = (
                BrowserType.EDGE
                if request.store == ScanStore.EDGE
                else BrowserType.CHROME
            )
            results = analyzer.analyze_extension(
                request.extension_id,
                browser=browser_type,
                progress_callback=progress_callback,
            )

        if not results:
            return ScanOutput(
                success=False,
                results=None,
                error="Analysis returned no results — extension may not exist or is inaccessible.",
                extension_dir="",
                json_report_path="",
                html_report_path="",
            )

        ext_dir = results.get("extension_dir", "") or ""
        json_path, html_path = self._find_report_paths(request.extension_id)

        return ScanOutput(
            success=True,
            results=results,
            error=None,
            extension_dir=ext_dir,
            json_report_path=json_path,
            html_report_path=html_path,
        )

    def _find_report_paths(self, extension_id: str) -> tuple[str, str]:
        """
        Locate JSON and HTML reports for a given extension id.

        Mirrors the heuristics used by the CLI/API so callers don't have to duplicate
        this logic.
        """
        reports_dir = self.reports_dir

        # VSCode identifiers have dots — sanitize the same way the report generator does
        import re as _re

        safe_id = _re.sub(r"[^\w\-.]", "_", extension_id)

        # JSON report
        json_path = ""
        for candidate_name in [
            f"{extension_id}_analysis.json",
            f"vscode_{safe_id}_analysis.json",
        ]:
            candidate = reports_dir / candidate_name
            if candidate.exists():
                json_path = str(candidate)
                break

        # HTML report
        html_path = ""
        for candidate_name in [
            f"{extension_id}_threat_analysis_report.html",
            f"vscode_{safe_id}_threat_analysis_report.html",
        ]:
            candidate = reports_dir / candidate_name
            if candidate.exists():
                html_path = str(candidate)
                break

        return json_path, html_path

