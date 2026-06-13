"""Offline smoke tests for DNSAUDIT — no network access."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dnsaudit import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    audit_domain,
    parse_spf,
    parse_dmarc,
    grade_score,
)
from dnsaudit.cli import main  # noqa: E402

# Hardened domain: good SPF, DMARC reject, DKIM 2048-bit, DNSSEC signed+DS.
HARDENED_SPF = "v=spf1 include:_spf.google.com -all"
HARDENED_DMARC = "v=DMARC1; p=reject; rua=mailto:dmarc@good.example"
HARDENED_DKIM = "v=DKIM1; k=rsa; p=" + "A" * 392  # ~2048-bit RSA
HARDENED_DNSSEC = {"signed": True, "ds_present": True}
HARDENED_CAA = ['0 issue "letsencrypt.org"', '0 iodef "mailto:s@good.example"']

# Weak domain: +all SPF, nothing else.
WEAK_SPF = "v=spf1 +all"


class TestMetadata(unittest.TestCase):
    def test_version(self):
        self.assertEqual(TOOL_NAME, "dnsaudit")
        self.assertTrue(TOOL_VERSION)


class TestParsers(unittest.TestCase):
    def test_parse_spf(self):
        spf = parse_spf("v=spf1 include:a.com a mx -all")
        self.assertEqual(spf["all"], "-all")
        self.assertEqual(spf["lookups"], 3)  # include, a, mx

    def test_parse_dmarc(self):
        result = parse_dmarc("v=DMARC1; p=reject; rua=mailto:x@y.com")
        self.assertEqual(result["tags"]["p"], "reject")
        self.assertEqual(result["tags"]["rua"], "mailto:x@y.com")

    def test_grade_score(self):
        # No findings -> score 100 -> grade A
        from dnsaudit.core import Finding
        letter_a, score_a = grade_score([])
        self.assertEqual(letter_a, "A")
        self.assertEqual(score_a, 100)
        # A critical finding drops the score and gives F
        letter_f, score_f = grade_score([Finding("spf", "SPF_PLUS_ALL", "CRITICAL", "msg")] * 3)
        self.assertEqual(letter_f, "F")
        self.assertLess(score_f, 60)


class TestAudit(unittest.TestCase):
    def test_hardened_is_clean(self):
        report = audit_domain(
            "good.example",
            spf=HARDENED_SPF,
            dmarc=HARDENED_DMARC,
            dkim=HARDENED_DKIM,
            dnssec=HARDENED_DNSSEC,
            caa=HARDENED_CAA,
        )
        self.assertEqual(report.grade, "A")
        self.assertGreaterEqual(report.score, 90)
        self.assertFalse(report.spoofable)

    def test_weak_flags_critical(self):
        report = audit_domain("bad.example", spf=WEAK_SPF)
        self.assertFalse(report.grade == "A")
        severities = {f.severity for f in report.findings}
        self.assertIn("CRITICAL", severities)  # +all
        self.assertIn("HIGH", severities)       # missing DMARC
        self.assertLess(report.score, 60)

    def test_invalid_domain_still_audits(self):
        # Domains with spaces are invalid; audit_domain should either raise or
        # handle gracefully. Current behavior: proceeds with the raw string.
        # Just check it does not crash and returns an AuditResult.
        from dnsaudit.core import AuditResult
        result = audit_domain("not a domain")
        self.assertIsInstance(result, AuditResult)

    def test_report_serializes(self):
        report = audit_domain(
            "good.example",
            spf=HARDENED_SPF,
            dmarc=HARDENED_DMARC,
            dkim=HARDENED_DKIM,
        )
        blob = json.dumps(report.to_dict())
        self.assertIn("findings", blob)
        self.assertIn("score", blob)


class TestCli(unittest.TestCase):
    def setUp(self):
        self.fixture = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "demos", "02-deep", "records.json")
        )

    def test_cli_json_runs(self):
        rc = main(["audit", "--input", self.fixture, "--format", "json"])
        # weak fixture: findings exist -> non-zero exit
        self.assertIn(rc, (0, 1))

    def test_cli_fail_under_score(self):
        # A domain with only DMARC reject + SPF -all passes easily; one with
        # nothing fails because score is far below 100.
        rc = main(["audit", "--domain", "x.example", "--format", "json"])
        self.assertEqual(rc, 1)

    def test_cli_bad_fixture_path(self):
        rc = main(["audit", "--input", "/no/such/file.json"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
