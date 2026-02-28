#!/usr/bin/env python3
"""
JsVulnDetector – Artemis module that detects vulnerable client-side JavaScript
libraries using a curated subset of the Retire.js vulnerability database.

The database is restricted to **XSS vulnerabilities** that are commonly
exploitable when the affected library is loaded on a page.  Vulnerability
classes that require very specific (and rare) application-level usage patterns
— such as prototype pollution, ReDoS, or server-side path traversal — are
excluded to minimise false positives.

Each vulnerability entry in ``jsrepository.json`` carries an
``exploitability_note`` field that documents *why* it is included and under
what conditions it is exploitable.

Scope
-----
Only external scripts referenced via ``<script src="...">``.  Inline scripts
are intentionally excluded to keep the module fast and avoid false positives
from minified / transpiled bundles.

Severity filtering
------------------
The ``JS_VULN_DETECTOR_MIN_SEVERITY`` configuration option (default: ``high``)
controls the minimum severity level that will be reported.  With the default,
only high-severity XSS vulnerabilities with well-documented, frequently
exploitable attack vectors are surfaced.

Per-page limits
---------------
* At most ``MAX_SCRIPTS_PER_PAGE`` script sources are inspected.
* Script content is fetched (to attempt version extraction) only when the URL
  itself does not reveal the version.  The fetched content is truncated to
  ``MAX_SCRIPT_CONTENT_BYTES`` to protect against very large bundles.
"""
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

import bs4
from karton.core import Task
from packaging.version import InvalidVersion, Version

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url

MAX_SCRIPTS_PER_PAGE = 25
MAX_SCRIPT_CONTENT_BYTES = 256 * 1024  # 256 KB

DB_PATH = Path(__file__).parent / "data" / "jsrepository.json"

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _load_db() -> Dict[str, Any]:
    with open(DB_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _severity_rank(s: str) -> int:
    return _SEVERITY_RANK.get(s.lower(), 0)


def _min_severity_rank() -> int:
    return _severity_rank(Config.Modules.JsVulnDetector.JS_VULN_DETECTOR_MIN_SEVERITY)


def _extract_version(text: str, patterns: List[str]) -> Optional[str]:
    """Return the first capturing group matched by any pattern, or *None*."""
    for raw_pattern in patterns:
        try:
            match = re.search(raw_pattern, text, re.IGNORECASE)
        except re.error:
            continue
        if match:
            groups = match.groups()
            if groups and groups[0]:
                return groups[0].strip()
    return None


def _version_is_vulnerable(version_str: str, vuln_entry: Dict[str, Any]) -> bool:
    """
    Return *True* when *version_str* falls within the affected range described
    by *vuln_entry*, which may contain ``"atOrAbove"`` and/or ``"below"`` keys.
    """
    try:
        version = Version(version_str)
    except InvalidVersion:
        return False

    at_or_above = vuln_entry.get("atOrAbove")
    below = vuln_entry.get("below")

    if at_or_above:
        try:
            if version < Version(at_or_above):
                return False
        except InvalidVersion:
            return False

    if below:
        try:
            if version >= Version(below):
                return False
        except InvalidVersion:
            return False

    return True


def check_library(
    lib_name: str,
    lib_info: Dict[str, Any],
    script_url: str,
    script_content: Optional[str],
    min_severity_rank: int = 0,
) -> Optional[Dict[str, Any]]:
    """
    Try to detect *lib_name* in the given script and, if a known-vulnerable
    version is found, return a finding dictionary.  Returns *None* when no
    vulnerability is detected or all matching vulnerabilities are below the
    minimum severity threshold.

    The URL path (``script_url``) is always tried first so that fetching the
    script content can be skipped for the common case where the version appears
    in the file name.
    """
    extractors = lib_info.get("extractors", {})

    detected_version: Optional[str] = None
    for key in ("filename", "uri"):
        detected_version = _extract_version(script_url, extractors.get(key, []))
        if detected_version:
            break

    if not detected_version and script_content is not None:
        detected_version = _extract_version(script_content, extractors.get("filecontent", []))

    if not detected_version:
        return None

    matching: List[Dict[str, Any]] = [
        v
        for v in lib_info.get("vulnerabilities", [])
        if _version_is_vulnerable(detected_version, v) and _severity_rank(v.get("severity", "unknown")) >= min_severity_rank
    ]
    if not matching:
        return None

    cves: List[str] = []
    severities: List[str] = []
    info_urls: List[str] = []
    exploit_types: List[str] = []
    for vuln in matching:
        ids = vuln.get("identifiers", {})
        cves.extend(ids.get("CVE", []))
        severities.append(vuln.get("severity", "unknown"))
        info_urls.extend(vuln.get("info", []))
        if vuln.get("exploit_type"):
            exploit_types.append(vuln["exploit_type"])

    worst_severity = max(severities, key=_severity_rank) if severities else "unknown"

    return {
        "library": lib_name,
        "detected_version": detected_version,
        "script_url": script_url,
        "cves": sorted(set(cves)),
        "severity": worst_severity,
        "exploit_type": sorted(set(exploit_types))[0] if exploit_types else "unknown",
        "info_urls": list(dict.fromkeys(info_urls)),
    }


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class JsVulnDetector(ArtemisBase):
    """
    Detects vulnerable client-side JavaScript libraries (e.g. jQuery, Bootstrap,
    AngularJS) loaded via ``<script src="...">``, using a curated subset of the
    Retire.js vulnerability database focused on XSS vulnerabilities that are
    commonly exploitable.

    The database is restricted to vulnerability classes where the presence of
    an outdated library version creates a realistic, exploitable risk — primarily
    XSS via DOM manipulation, sanitizer bypasses, or expression injection.

    Vulnerabilities that require rare application-level usage patterns (prototype
    pollution, ReDoS, server-side path traversal) are excluded.  Each database
    entry includes an ``exploitability_note`` documenting the attack vector and
    conditions under which it is exploitable.

    Results are further filtered by the ``JS_VULN_DETECTOR_MIN_SEVERITY``
    setting (default: ``high``).
    """

    identity = "js_vuln_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._db: Dict[str, Any] = _load_db()

    def _fetch_script(self, script_url: str) -> Optional[str]:
        """
        Fetch *script_url* and return its decoded text content, or *None* on
        any error (connection failure, non-200 status, binary content, …).
        Content larger than ``MAX_SCRIPT_CONTENT_BYTES`` is ignored.
        """
        try:
            response = self.forgiving_http_get(script_url, max_size=MAX_SCRIPT_CONTENT_BYTES)
            if response is None:
                return None
            if response.status_code != 200:
                return None
            content_type = response.headers.get("content-type", "")
            if "html" in content_type.lower():
                return None
            return response.content
        except Exception as exc:
            self.log.debug("Could not fetch script %s: %s", script_url, exc)
            return None

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        min_sev = _min_severity_rank()

        try:
            page_response = self.http_get(url)
        except Exception as exc:
            self.log.error("Failed to fetch %s: %s", url, exc)
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason=str(exc),
                data={"findings": [], "scripts_checked": 0},
            )
            return

        if page_response.status_code != 200:
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                status_reason=None,
                data={"findings": [], "scripts_checked": 0},
            )
            return

        content_type = page_response.headers.get("content-type", "")
        if "html" not in content_type.lower():
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                status_reason=None,
                data={"findings": [], "scripts_checked": 0},
            )
            return

        soup = bs4.BeautifulSoup(page_response.content_bytes, "html.parser")
        script_tags = soup.find_all("script", src=True)

        findings: List[Dict[str, Any]] = []
        scripts_checked = 0

        for tag in script_tags[:MAX_SCRIPTS_PER_PAGE]:
            src: str = (tag.get("src") or "").strip()
            if not src:
                continue

            script_url = urllib.parse.urljoin(url, src)
            url_path = urllib.parse.urlparse(script_url).path.lower()

            script_content: Optional[str] = None
            content_fetched = False
            scripts_checked += 1

            for lib_name, lib_info in self._db.items():
                finding = check_library(lib_name, lib_info, url_path, script_content, min_sev)

                if finding is None and not content_fetched:
                    script_content = self._fetch_script(script_url)
                    content_fetched = True
                    finding = check_library(lib_name, lib_info, url_path, script_content, min_sev)

                if finding is not None:
                    finding["script_url"] = script_url
                    findings.append(finding)

        if findings:
            messages = []
            for f in findings:
                cve_str = ", ".join(f["cves"]) if f["cves"] else "no CVE listed"
                messages.append(
                    f"{f['library']} {f['detected_version']} "
                    f"loaded from {f['script_url']} has known {f['exploit_type'].upper()} "
                    f"vulnerabilities ({cve_str}). "
                    f"Please upgrade to the latest stable version."
                )
            status = TaskStatus.INTERESTING
            status_reason = "; ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={"findings": findings, "scripts_checked": scripts_checked},
        )


if __name__ == "__main__":
    JsVulnDetector().loop()
