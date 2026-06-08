"""Tests for the DNSAUDIT deep posture engine + typosquat generator.

No network is used — every check runs against supplied records.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dnsaudit import (  # noqa: E402
    TOOL_NAME, TOOL_VERSION,
    audit_domain, parse_spf, parse_dmarc, parse_dkim, parse_caa,
    parse_dnssec, grade_score, generate_typosquats,
)
from dnsaudit.cli import main  # noqa: E402


class TestParsers(unittest.TestCase):
    def test_spf_lookups_and_all(self):
        spf = parse_spf("v=spf1 include:a.com include:b.com mx ~all")
        self.assertTrue(spf["present"])
        self.assertEqual(spf["all"], "~all")
        self.assertEqual(spf["lookups"], 3)  # 2 includes + mx
        self.assertEqual(spf["includes"], ["a.com", "b.com"])

    def test_spf_invalid(self):
        self.assertFalse(parse_spf("not an spf record")["present"])
        self.assertFalse(parse_spf(None)["present"])

    def test_dmarc_tags(self):
        d = parse_dmarc("v=DMARC1; p=reject; rua=mailto:x@y.com; pct=100")
        self.assertTrue(d["present"])
        self.assertEqual(d["tags"]["p"], "reject")
        self.assertEqual(d["tags"]["rua"], "mailto:x@y.com")

    def test_dkim_key_bits_and_revoked(self):
        big = "v=DKIM1; k=rsa; p=" + "A" * 392  # ~2048-bit modulus
        self.assertEqual(parse_dkim(big)["key_bits"], 2048)
        revoked = parse_dkim("v=DKIM1; k=rsa; p=")
        self.assertTrue(revoked["revoked"])

    def test_caa_parse(self):
        caa = parse_caa(['0 issue "letsencrypt.org"',
                         '0 iodef "mailto:s@x.com"'])
        self.assertTrue(caa["present"])
        self.assertIn("letsencrypt.org", caa["issue"])
        self.assertEqual(caa["iodef"], ["mailto:s@x.com"])

    def test_dnssec_forms(self):
        self.assertTrue(parse_dnssec(True)["signed"])
        self.assertTrue(parse_dnssec("signed")["signed"])
        self.assertFalse(parse_dnssec({"signed": False})["signed"])


class TestAudit(unittest.TestCase):
    def test_strong_domain_grades_high(self):
        res = audit_domain(
            "good.com",
            spf="v=spf1 include:_spf.google.com -all",
            dmarc="v=DMARC1; p=reject; rua=mailto:d@good.com; pct=100",
            dkim="v=DKIM1; k=rsa; p=" + "A" * 392,
            dnssec={"signed": True, "algorithm": 13, "ds_present": True},
            caa=['0 issue "letsencrypt.org"', '0 iodef "mailto:s@good.com"'])
        self.assertIn(res.grade, ("A", "B"))
        self.assertFalse(res.spoofable)

    def test_weak_domain_is_spoofable_and_low(self):
        res = audit_domain(
            "bad.com",
            spf="v=spf1 +all",
            dmarc="v=DMARC1; p=none")
        self.assertTrue(res.spoofable)
        self.assertEqual(res.grade, "F")
        codes = {f.code for f in res.findings}
        self.assertIn("SPF_PLUS_ALL", codes)
        self.assertIn("DMARC_P_NONE", codes)
        self.assertIn("DKIM_MISSING", codes)
        # CRITICAL present
        self.assertTrue(any(f.severity == "CRITICAL" for f in res.findings))

    def test_missing_everything(self):
        res = audit_domain("empty.com")
        self.assertTrue(res.spoofable)
        codes = {f.code for f in res.findings}
        self.assertIn("SPF_MISSING", codes)
        self.assertIn("DMARC_MISSING", codes)
        self.assertIn("DNSSEC_UNSIGNED", codes)
        self.assertIn("CAA_MISSING", codes)

    def test_grade_score_monotonic(self):
        from dnsaudit.core import Finding
        good = grade_score([])
        bad = grade_score([Finding("spf", "X", "CRITICAL", "m")])
        self.assertEqual(good[0], "A")
        self.assertLess(bad[1], good[1])

    def test_demo_record(self):
        path = os.path.join(os.path.dirname(__file__), "..",
                            "demos", "02-deep", "records.json")
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        res = audit_domain(data["domain"], data["spf"], data["dmarc"],
                           data["dkim"], dnssec=data["dnssec"],
                           caa=data["caa"], with_typosquats=True)
        codes = {f.code for f in res.findings}
        for expected in ("SPF_NEUTRAL_ALL", "SPF_TOO_MANY_LOOKUPS",
                         "DMARC_P_NONE", "DMARC_PCT_PARTIAL", "DMARC_NO_RUA",
                         "DKIM_TEST_MODE", "DKIM_WEAK_KEY",
                         "DNSSEC_NO_DS", "DNSSEC_WEAK_ALGO", "CAA_MISSING"):
            self.assertIn(expected, codes, f"missing {expected}")
        self.assertIn(res.grade, ("D", "F"))
        self.assertTrue(res.typosquats)


class TestTyposquat(unittest.TestCase):
    def test_families_present(self):
        typos = generate_typosquats("paypal.com")
        fuzzers = {t["fuzzer"] for t in typos}
        for fam in ("insertion", "omission", "repetition", "replacement",
                    "transposition", "bitsquatting", "homoglyph",
                    "hyphenation", "vowel-swap", "addition", "tld-swap",
                    "subdomain"):
            self.assertIn(fam, fuzzers, f"missing fuzzer {fam}")
        domains = {t["domain"] for t in typos}
        # classic dnstwist results
        self.assertIn("paypa1.com", domains)   # homoglyph l->1
        self.assertIn("paypall.com", domains)  # repetition
        self.assertIn("paypal.net", domains)   # tld-swap
        self.assertNotIn("paypal.com", domains)  # original excluded

    def test_dedup_and_subdomain_split(self):
        typos = generate_typosquats("example.co.uk")
        doms = [t["domain"] for t in typos]
        self.assertEqual(len(doms), len(set(doms)))  # no dups
        # TLD preserved as co.uk on non-tld-swap fuzzers
        self.assertTrue(any(d.endswith(".co.uk") for d in typos
                            for d in [d["domain"]] if d["fuzzer"] == "omission"))

    def test_extra_tld_and_limit(self):
        typos = generate_typosquats("acme.com", extra_tlds=["zip"])
        self.assertIn("acme.zip", {t["domain"] for t in typos})
        capped = generate_typosquats("acme.com", max_results=15)
        self.assertEqual(len(capped), 15)


class TestCLI(unittest.TestCase):
    def test_version_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_audit_json_nonzero_on_findings(self):
        rc = main(["audit", "--domain", "bad.com", "--spf", "v=spf1 +all",
                   "--format", "json"])
        self.assertEqual(rc, 1)

    def test_audit_strong_zero(self):
        rc = main(["audit", "--domain", "g.com",
                   "--spf", "v=spf1 -all",
                   "--dmarc", "v=DMARC1; p=reject; rua=mailto:d@g.com",
                   "--dkim", "v=DKIM1; k=rsa; p=" + "A" * 392,
                   "--dnssec", "--format", "json"])
        # DKIM present, SPF -all, DMARC reject => not spoofable; CAA missing is
        # only LOW, DNSSEC signed; worst is below HIGH -> exit 0.
        self.assertEqual(rc, 0)

    def test_typosquat_subcommand_json(self):
        rc = main(["typosquat", "--domain", "paypal.com",
                   "--format", "json", "--limit", "20"])
        self.assertEqual(rc, 1)  # surface exists -> nonzero

    def test_audit_with_input_file(self):
        path = os.path.join(os.path.dirname(__file__), "..",
                            "demos", "02-deep", "records.json")
        rc = main(["audit", "--input", path, "--format", "json",
                   "--typosquats"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
