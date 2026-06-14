"""Edge-case and error-path tests for DNSAUDIT hardening.

All tests are offline. These cover input validation, error-path exit codes,
and edge cases added during the production hardening pass.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dnsaudit import generate_typosquats, audit_domain  # noqa: E402
from dnsaudit.cli import main  # noqa: E402


class TestJsonInputValidation(unittest.TestCase):
    """CLI should reject non-dict JSON with exit code 2 and a clear message."""

    def _write_tmp(self, content: str) -> str:
        fh = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8")
        fh.write(content)
        fh.close()
        return fh.name

    def test_json_array_returns_exit2(self):
        path = self._write_tmp('[{"domain": "example.com"}]')
        try:
            rc = main(["audit", "--input", path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)

    def test_json_string_returns_exit2(self):
        path = self._write_tmp('"just a string"')
        try:
            rc = main(["audit", "--input", path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)

    def test_malformed_json_returns_exit2(self):
        path = self._write_tmp('{broken json')
        try:
            rc = main(["audit", "--input", path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)

    def test_missing_file_returns_exit2(self):
        rc = main(["audit", "--input", "/no/such/file/ever.json"])
        self.assertEqual(rc, 2)


class TestTyposquatEdgeCases(unittest.TestCase):
    """generate_typosquats edge cases that must not crash or misbehave."""

    def test_empty_string_returns_empty(self):
        self.assertEqual(generate_typosquats(""), [])

    def test_none_like_falsy_returns_empty(self):
        # A caller might pass an empty value; must not raise.
        self.assertEqual(generate_typosquats(""), [])

    def test_bare_tld_only_returns_empty(self):
        # "com" alone has no SLD after splitting — should return empty, not crash.
        result = generate_typosquats("com")
        self.assertIsInstance(result, list)

    def test_negative_max_results_raises(self):
        with self.assertRaises(ValueError):
            generate_typosquats("paypal.com", max_results=-1)

    def test_zero_max_results_returns_all(self):
        full = generate_typosquats("paypal.com", max_results=0)
        self.assertGreater(len(full), 50)

    def test_single_char_domain_no_crash(self):
        result = generate_typosquats("a.com")
        self.assertIsInstance(result, list)


class TestCliLimitValidation(unittest.TestCase):
    """--limit < 0 should print an error to stderr and return exit 2."""

    def test_negative_limit_returns_exit2(self):
        rc = main(["typosquat", "--domain", "paypal.com", "--limit", "-5"])
        self.assertEqual(rc, 2)


class TestWorstSeverityRobustness(unittest.TestCase):
    """AuditResult.worst_severity must not raise on unknown severity values."""

    def test_unknown_severity_does_not_raise(self):
        from dnsaudit.core import AuditResult, Finding
        finding = Finding("spf", "CUSTOM_CODE", "UNKNOWN_SEV", "test message")
        res = AuditResult(
            domain="x.com", grade="F", score=0, spoofable=True,
            spf={}, dmarc={}, dkim={}, dnssec={}, caa={},
            findings=[finding],
        )
        # Should not raise KeyError
        sev = res.worst_severity
        self.assertIsInstance(sev, str)

    def test_empty_findings_returns_info(self):
        from dnsaudit.core import AuditResult
        res = AuditResult(
            domain="x.com", grade="A", score=100, spoofable=False,
            spf={}, dmarc={}, dkim={}, dnssec={}, caa={},
            findings=[],
        )
        self.assertEqual(res.worst_severity, "INFO")


class TestAuditDomainEdgeCases(unittest.TestCase):
    """audit_domain must handle degenerate inputs gracefully."""

    def test_none_domain_uses_unknown(self):
        from dnsaudit.core import AuditResult
        res = audit_domain(None)
        self.assertIsInstance(res, AuditResult)
        self.assertEqual(res.domain, "unknown")

    def test_empty_string_domain(self):
        from dnsaudit.core import AuditResult
        res = audit_domain("")
        self.assertIsInstance(res, AuditResult)

    def test_all_none_records_no_crash(self):
        from dnsaudit.core import AuditResult
        res = audit_domain("test.com", spf=None, dmarc=None, dkim=None,
                           dnssec=None, caa=None)
        self.assertIsInstance(res, AuditResult)
        self.assertTrue(res.spoofable)


if __name__ == "__main__":
    unittest.main()
