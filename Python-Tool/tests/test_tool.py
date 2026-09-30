"""Unit tests for IOCX.  Run with:  python3 -m unittest discover -v tests"""
import contextlib
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import tool  # noqa: E402


def run(text, types=None, **kw):
    """Helper: run extraction on `text` and return the IOCStore."""
    store = tool.IOCStore()
    tool.process_text(text, "test", store, types or tool.IOC_TYPES,
                      kw.get("include_private", False), kw.get("allowlist", set()))
    return store


class TestRefang(unittest.TestCase):
    def test_refang_and_defang(self):
        self.assertEqual(tool.refang("hxxp://evil[.]com"), "http://evil.com")
        self.assertEqual(tool.refang("a[@]b(.)org"), "a@b.org")
        self.assertEqual(tool.defang_value("url", "http://evil.com"), "hxxp://evil[.]com")
        self.assertEqual(tool.defang_value("md5", "abc"), "abc")


class TestExtraction(unittest.TestCase):
    def test_ipv4_valid_and_invalid(self):
        s = run("bad 8.8.4.4 and 999.1.1.1 and 1.2.3.4.5", ["ipv4"])
        self.assertEqual(set(s.counts["ipv4"]), {"8.8.4.4"})

    def test_private_ips_filtered_unless_requested(self):
        self.assertEqual(run("10.0.0.5 127.0.0.1", ["ipv4"]).unique("ipv4"), 0)
        self.assertEqual(run("10.0.0.5", ["ipv4"], include_private=True).unique("ipv4"), 1)

    def test_ipv6_ignores_timestamps(self):
        s = run("at 12:30:45 host 2a01:4f8:c17:1234::2", ["ipv6"])
        self.assertEqual(set(s.counts["ipv6"]), {"2a01:4f8:c17:1234::2"})

    def test_domains_reject_filenames(self):
        s = run("see setup.py run.sh evil-site.top", ["domain"])
        self.assertEqual(set(s.counts["domain"]), {"evil-site.top"})

    def test_urls_strip_trailing_punctuation(self):
        s = run("visit http://a.com/x, then (https://b.org/y).", ["url"])
        self.assertEqual(set(s.counts["url"]), {"http://a.com/x", "https://b.org/y"})

    def test_hashes(self):
        md5 = "44d88612fea8a8f36de82e1278abb02f"
        s = run(f"{md5} 12345678901234567890123456789012", ["md5"])
        self.assertEqual(set(s.counts["md5"]), {md5})   # all-digit string ignored

    def test_cve_mitre(self):
        s = run("cve-2021-4034 T1059.001", ["cve", "mitre"])
        self.assertIn("CVE-2021-4034", s.counts["cve"])
        self.assertIn("T1059.001", s.counts["mitre"])

    def test_counts_repeated_values(self):
        s = run("1.1.1.1 1.1.1.1 1.1.1.1", ["ipv4"])
        self.assertEqual(s.counts["ipv4"]["1.1.1.1"], 3)

    def test_defanged_input_is_found(self):
        s = run("C2: hxxps://bad[.]xyz/a from 8[.]8[.]8[.]8")
        self.assertIn("https://bad.xyz/a", s.counts["url"])
        self.assertIn("8.8.8.8", s.counts["ipv4"])


class TestFilteringAndTags(unittest.TestCase):
    def test_allowlist_matches_subdomains_and_emails(self):
        al = {"good.com"}
        self.assertTrue(tool.is_allowlisted("domain", "cdn.good.com", al))
        self.assertTrue(tool.is_allowlisted("email", "a@good.com", al))
        self.assertFalse(tool.is_allowlisted("domain", "evilgood.com", al))

    def test_annotations(self):
        self.assertIn("suspicious-tld", tool.annotate("domain", "x.top"))
        self.assertIn("ip-in-url", tool.annotate("url", "http://1.2.3.4/a"))
        self.assertIn("executable-download", tool.annotate("url", "http://x.com/a.exe"))


class TestCLI(unittest.TestCase):
    def test_parse_types(self):
        self.assertEqual(tool.parse_types("domain,ipv4"), ["ipv4", "domain"])
        with self.assertRaises(ValueError):
            tool.parse_types("bogus")

    def test_main_exit_codes(self):
        # capture stdout/stderr so the test output stays clean
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(tool.main(["-t", "8.8.8.8", "-f", "txt"]), 0)
            self.assertEqual(tool.main(["-t", "nothing", "-f", "txt"]), 1)
            self.assertEqual(tool.main(["missing_file.txt"]), 2)

    def test_renderers_produce_output(self):
        s = run("8.8.8.8 evil.top")
        res = tool.build_result(s, tool.IOC_TYPES, [{"name": "t", "sha256": "0"}], False, 1)
        for fmt in ("json", "csv", "txt", "md", "html"):
            self.assertTrue(tool.render(fmt, res, tool.Colors(False)))


if __name__ == "__main__":
    unittest.main()
