"""Offline smoke tests for DNSAUDIT — no network access."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dnsaudit import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    DictResolver,
    audit_domain,
    parse_spf,
    parse_dmarc,
    grade,
)
from dnsaudit.cli import main  # noqa: E402


HARDENED = DictResolver(
    txt_records={
        "good.example": ["v=spf1 include:_spf.google.com -all"],
        "_dmarc.good.example": ["v=DMARC1; p=reject; rua=mailto:dmarc@good.example"],
        "default._domainkey.good.example": ["v=DKIM1; k=rsa; p=MIGfMA0"],
        "_caa.good.example": ["0 issue \"letsencrypt.org\""],
    },
    dnssec=["good.example"],
)

WEAK = DictResolver(
    txt_records={
        "bad.example": ["v=spf1 +all"],
    },
    dnssec=[],
)


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
        tags = parse_dmarc("v=DMARC1; p=reject; rua=mailto:x@y.com")
        self.assertEqual(tags["p"], "reject")
        self.assertEqual(tags["rua"], "mailto:x@y.com")

    def test_grade(self):
        self.assertEqual(grade(95), "A")
        self.assertEqual(grade(50), "F")


class TestAudit(unittest.TestCase):
    def test_hardened_is_clean(self):
        report = audit_domain("good.example", HARDENED)
        self.assertTrue(report.ok)
        self.assertEqual(report.grade, "A")
        self.assertGreaterEqual(report.score, 90)

    def test_weak_flags_critical(self):
        report = audit_domain("bad.example", WEAK)
        self.assertFalse(report.ok)
        severities = {f.severity for f in report.findings}
        self.assertIn("critical", severities)  # +all
        self.assertIn("high", severities)      # missing DMARC
        self.assertLess(report.score, 60)

    def test_invalid_domain(self):
        with self.assertRaises(ValueError):
            audit_domain("not a domain", WEAK)

    def test_report_serializes(self):
        report = audit_domain("good.example", HARDENED)
        blob = json.dumps(report.to_dict())
        self.assertIn("findings", blob)
        self.assertIn("score", blob)


class TestCli(unittest.TestCase):
    def setUp(self):
        self.fixture = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "weakcorp.example.json")
        )

    def test_cli_json_runs(self):
        rc = main(["scan", "weakcorp.example", "--fixture", self.fixture, "--format", "json"])
        # weak-but-not-broken fixture: findings exist -> non-zero exit
        self.assertIn(rc, (0, 1))

    def test_cli_fail_under(self):
        rc = main(["scan", "weakcorp.example", "--fixture", self.fixture,
                   "--format", "json", "--fail-under", "100"])
        self.assertEqual(rc, 1)

    def test_cli_bad_fixture_path(self):
        rc = main(["scan", "x.example", "--fixture", "/no/such/file.json"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
