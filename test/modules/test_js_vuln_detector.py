import unittest
from test.base import ArtemisModuleTestCase
from unittest.mock import patch

import requests_mock as requests_mock_module
from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.js_vuln_detector import (
    JsVulnDetector,
    _version_is_vulnerable,
    check_library,
)


class TestVersionIsVulnerable(unittest.TestCase):
    """Unit tests for the pure version-comparison helper."""

    def test_below_only_inside_range(self) -> None:
        self.assertTrue(_version_is_vulnerable("1.12.0", {"below": "3.5.0"}))

    def test_below_only_at_boundary(self) -> None:
        self.assertFalse(_version_is_vulnerable("3.5.0", {"below": "3.5.0"}))

    def test_below_only_above_range(self) -> None:
        self.assertFalse(_version_is_vulnerable("3.6.0", {"below": "3.5.0"}))

    def test_at_or_above_and_below_inside(self) -> None:
        self.assertTrue(_version_is_vulnerable("1.12.0", {"atOrAbove": "1.0.3", "below": "3.4.0"}))

    def test_at_or_above_and_below_below_range(self) -> None:
        self.assertFalse(_version_is_vulnerable("1.0.2", {"atOrAbove": "1.0.3", "below": "3.4.0"}))

    def test_at_or_above_inclusive(self) -> None:
        self.assertTrue(_version_is_vulnerable("1.0.3", {"atOrAbove": "1.0.3", "below": "3.4.0"}))

    def test_invalid_version_string(self) -> None:
        self.assertFalse(_version_is_vulnerable("not-a-version", {"below": "3.5.0"}))


class TestCheckLibrary(unittest.TestCase):
    """Unit tests for the pure check_library() function."""

    def _jquery_lib(self):  # type: ignore
        import json
        from pathlib import Path
        db_path = Path(__file__).parents[2] / "artemis" / "modules" / "data" / "jsrepository.json"
        return json.loads(db_path.read_text())["jquery"]

    def test_vulnerable_jquery_from_url(self) -> None:
        result = check_library("jquery", self._jquery_lib(), "/js/jquery-1.12.0.min.js", None)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["library"], "jquery")
        self.assertEqual(result["detected_version"], "1.12.0")
        self.assertIn("CVE-2020-11022", result["cves"])
        self.assertIn("CVE-2020-11023", result["cves"])
        self.assertEqual(result["exploit_type"], "xss")

    def test_safe_jquery_from_url(self) -> None:
        result = check_library("jquery", self._jquery_lib(), "/js/jquery-3.7.0.min.js", None)
        self.assertIsNone(result)

    def test_version_extracted_from_content(self) -> None:
        content = "/*! jQuery JavaScript Library v1.8.3 | ... */"
        result = check_library("jquery", self._jquery_lib(), "/js/jquery.min.js", content)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["detected_version"], "1.8.3")

    def test_no_match_returns_none(self) -> None:
        result = check_library("jquery", self._jquery_lib(), "/js/app.js", "var foo = 1;")
        self.assertIsNone(result)

    def test_severity_filtering_excludes_medium(self) -> None:
        """With min_severity_rank=3 (high), medium-only CVEs should not be reported."""
        result = check_library("jquery", self._jquery_lib(), "/js/jquery-1.11.5.min.js", None, min_severity_rank=3)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertIn("CVE-2020-11022", result["cves"])
        self.assertNotIn("CVE-2015-9251", result["cves"])

    def test_severity_filtering_includes_all_at_zero(self) -> None:
        """With min_severity_rank=0, all CVEs should be included."""
        result = check_library("jquery", self._jquery_lib(), "/js/jquery-1.11.5.min.js", None, min_severity_rank=0)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertIn("CVE-2020-11022", result["cves"])
        self.assertIn("CVE-2015-9251", result["cves"])


class JsVulnDetectorTest(ArtemisModuleTestCase):
    karton_class = JsVulnDetector  # type: ignore

    def _make_task(self, host: str = "example.com", port: int = 80) -> Task:
        return Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": host, "port": port},
        )

    @patch("artemis.modules.js_vuln_detector._min_severity_rank", return_value=3)
    def test_vulnerable_jquery_detected(self, _mock_sev) -> None:
        """A page loading jQuery 1.12.0 must be reported as INTERESTING (XSS CVEs are high severity)."""
        html = (
            b"<!DOCTYPE html><html><head>"
            b'<script src="/js/jquery-1.12.0.min.js"></script>'
            b"</head><body></body></html>"
        )
        with requests_mock_module.Mocker() as m:
            m.get("http://example.com:80", content_type="text/html", content=html)
            m.get(
                "http://example.com:80/js/jquery-1.12.0.min.js",
                text="/*! jQuery JavaScript Library v1.12.0 */",
                headers={"content-type": "application/javascript"},
            )
            self.mock_db.reset_mock()
            self.run_task(self._make_task())

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        findings = call.kwargs["data"]["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["library"], "jquery")
        self.assertEqual(findings[0]["detected_version"], "1.12.0")
        self.assertIn("CVE-2020-11022", findings[0]["cves"])
        self.assertEqual(findings[0]["exploit_type"], "xss")

    @patch("artemis.modules.js_vuln_detector._min_severity_rank", return_value=3)
    def test_safe_jquery_not_reported(self, _mock_sev) -> None:
        """A page loading a safe jQuery version must be reported as OK."""
        html = (
            b"<!DOCTYPE html><html><head>"
            b'<script src="/js/jquery-3.7.0.min.js"></script>'
            b"</head><body></body></html>"
        )
        with requests_mock_module.Mocker() as m:
            m.get("http://example.com:80", content_type="text/html", content=html)
            m.get(
                "http://example.com:80/js/jquery-3.7.0.min.js",
                text="/*! jQuery v3.7.0 */",
                headers={"content-type": "application/javascript"},
            )
            self.mock_db.reset_mock()
            self.run_task(self._make_task())

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertEqual(call.kwargs["data"]["findings"], [])

    @patch("artemis.modules.js_vuln_detector._min_severity_rank", return_value=3)
    def test_no_scripts_ok(self, _mock_sev) -> None:
        """A page with no <script src> tags must be reported as OK."""
        html = b"<!DOCTYPE html><html><head></head><body><p>Hello</p></body></html>"
        with requests_mock_module.Mocker() as m:
            m.get("http://example.com:80", content_type="text/html", content=html)
            self.mock_db.reset_mock()
            self.run_task(self._make_task())

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertEqual(call.kwargs["data"]["findings"], [])

    @patch("artemis.modules.js_vuln_detector._min_severity_rank", return_value=3)
    def test_non_html_response_ok(self, _mock_sev) -> None:
        """A non-HTML endpoint (e.g. a JSON API) must be reported as OK."""
        with requests_mock_module.Mocker() as m:
            m.get(
                "http://example.com:80",
                text='{"status": "ok"}',
                headers={"content-type": "application/json"},
            )
            self.mock_db.reset_mock()
            self.run_task(self._make_task())

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)

    @patch("artemis.modules.js_vuln_detector._min_severity_rank", return_value=3)
    def test_multiple_vulnerable_libraries(self, _mock_sev) -> None:
        """Both vulnerable jQuery and Bootstrap on the same page must be detected."""
        html = (
            b"<!DOCTYPE html><html><head>"
            b'<script src="/js/jquery-1.11.0.min.js"></script>'
            b'<script src="/js/bootstrap-3.3.7.min.js"></script>'
            b"</head><body></body></html>"
        )
        with requests_mock_module.Mocker() as m:
            m.get("http://example.com:80", content_type="text/html", content=html)
            m.get(
                "http://example.com:80/js/jquery-1.11.0.min.js",
                text="/*! jQuery JavaScript Library v1.11.0 */",
                headers={"content-type": "application/javascript"},
            )
            m.get(
                "http://example.com:80/js/bootstrap-3.3.7.min.js",
                text="/*! * Bootstrap v3.3.7 */",
                headers={"content-type": "application/javascript"},
            )
            self.mock_db.reset_mock()
            self.run_task(self._make_task())

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        libs = {f["library"] for f in call.kwargs["data"]["findings"]}
        self.assertIn("jquery", libs)
        self.assertIn("bootstrap", libs)

    @patch("artemis.modules.js_vuln_detector._min_severity_rank", return_value=3)
    def test_medium_severity_filtered_out_by_default(self, _mock_sev) -> None:
        """With high severity threshold, jQuery 1.11.5 should only show high-severity XSS CVEs."""
        html = (
            b"<!DOCTYPE html><html><head>"
            b'<script src="/js/jquery-1.11.5.min.js"></script>'
            b"</head><body></body></html>"
        )
        with requests_mock_module.Mocker() as m:
            m.get("http://example.com:80", content_type="text/html", content=html)
            m.get(
                "http://example.com:80/js/jquery-1.11.5.min.js",
                text="/*! jQuery JavaScript Library v1.11.5 */",
                headers={"content-type": "application/javascript"},
            )
            self.mock_db.reset_mock()
            self.run_task(self._make_task())

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        findings = call.kwargs["data"]["findings"]
        self.assertEqual(len(findings), 1)
        all_cves = findings[0]["cves"]
        self.assertIn("CVE-2020-11022", all_cves)
        self.assertNotIn("CVE-2015-9251", all_cves)
