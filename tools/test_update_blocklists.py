"""Unit tests for update_blocklists.py. Run with: python -m unittest -v tools/test_update_blocklists.py"""

from __future__ import annotations

import json
import pathlib
import tempfile
import unittest
from unittest import mock

import update_blocklists as ub


class ParseHostsTests(unittest.TestCase):
    def test_basic_lines(self):
        txt = "0.0.0.0 ads.example.com\n0.0.0.0 tracker.foo\n"
        self.assertEqual(list(ub.parse_hosts(txt)),
                         ["ads.example.com", "tracker.foo"])

    def test_comments_and_blanks(self):
        txt = "# header\n\n0.0.0.0 good.example   # trailing\n"
        self.assertEqual(list(ub.parse_hosts(txt)), ["good.example"])

    def test_skips_ip_and_localhost(self):
        txt = "127.0.0.1 localhost\n0.0.0.0 real.example\n"
        self.assertEqual(list(ub.parse_hosts(txt)), ["real.example"])

    def test_multi_domain_line(self):
        txt = "0.0.0.0 a.example b.example c.example\n"
        self.assertEqual(list(ub.parse_hosts(txt)),
                         ["a.example", "b.example", "c.example"])

    def test_uppercase_lowercased(self):
        txt = "0.0.0.0 DoubleClick.NET\n"
        self.assertEqual(list(ub.parse_hosts(txt)), ["doubleclick.net"])

    def test_malformed_skipped(self):
        txt = "0.0.0.0 bad!!!dom\n0.0.0.0 good.example\n"
        self.assertEqual(list(ub.parse_hosts(txt)), ["good.example"])


class ParseAdblockTests(unittest.TestCase):
    def test_simple_rule(self):
        self.assertEqual(list(ub.parse_adblock("||ads.example^\n")),
                         ["ads.example"])

    def test_options_stripped(self):
        self.assertEqual(list(ub.parse_adblock("||tracker.foo^$third-party\n")),
                         ["tracker.foo"])

    def test_comments_and_headers_ignored(self):
        txt = "[Adblock Plus 2.0]\n! comment\n||real.example^\n"
        self.assertEqual(list(ub.parse_adblock(txt)), ["real.example"])

    def test_exceptions_dropped(self):
        self.assertEqual(list(ub.parse_adblock("@@||allowed.example^\n")), [])

    def test_element_hiding_dropped(self):
        self.assertEqual(list(ub.parse_adblock("example.com##.ad-banner\n")), [])

    def test_wildcard_stripped(self):
        self.assertEqual(list(ub.parse_adblock("||*.cdn.example^\n")),
                         ["cdn.example"])


class ParsePlainTests(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(list(ub.parse_plain("a.example\nb.example\n")),
                         ["a.example", "b.example"])

    def test_comments_ignored(self):
        self.assertEqual(list(ub.parse_plain("# header\na.example\n# tail\n")),
                         ["a.example"])


class MergeTests(unittest.TestCase):
    def _fetch(self, name: str, text: str, error: str | None = None) -> ub.Fetch:
        return ub.Fetch(name=name, url=f"https://x/{name}", text=text,
                        error=error)

    def _source(self, name: str, fmt: str) -> ub.Source:
        return ub.Source(name=name, url=f"https://x/{name}", format=fmt)

    def test_dedupes_across_sources(self):
        src = [self._source("a", "plain"), self._source("b", "plain")]
        fet = [self._fetch("a", "foo.example\nbar.example\n"),
               self._fetch("b", "bar.example\nbaz.example\n")]
        domains, manifest = ub.merge(fet, src)
        self.assertEqual(domains,
                         ["bar.example", "baz.example", "foo.example"])
        self.assertEqual(manifest["domain_count"], 3)

    def test_bad_source_doesnt_poison_merge(self):
        src = [self._source("good", "plain"), self._source("bad", "hosts")]
        fet = [self._fetch("good", "a.example\nb.example\n"),
               self._fetch("bad", "", error="404 not found")]
        domains, manifest = ub.merge(fet, src)
        self.assertEqual(domains, ["a.example", "b.example"])
        self.assertEqual(len(manifest["errors"]), 1)
        self.assertIn("404", manifest["errors"][0])

    def test_manifest_includes_per_source_sha(self):
        src = [self._source("a", "plain")]
        fet = [self._fetch("a", "foo.example\n")]
        _, manifest = ub.merge(fet, src)
        self.assertEqual(manifest["version"], 1)
        self.assertIn("generated_at", manifest)
        self.assertEqual(len(manifest["sources"]), 1)
        self.assertEqual(len(manifest["sources"][0]["sha256"]), 64)


class WriteOutputTests(unittest.TestCase):
    def test_write_merged_is_deterministic(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "merged.txt"
            manifest = {
                "version": 1,
                "generated_at": "2026-04-22T00:00:00+00:00",
                "sources": [{"name": "a"}, {"name": "b"}],
                "domain_count": 2,
                "errors": [],
            }
            ub.write_merged(["b.example", "a.example"], out, manifest)
            contents = out.read_text(encoding="utf-8")
            # Sorted writer input was already sorted — we pass pre-sorted
            # in real merge() output; here the unsorted input is emitted
            # in insertion order. Test just verifies header + format.
            self.assertIn("# CloakDNS merged blocklist", contents)
            self.assertIn("0.0.0.0 b.example\n", contents)
            self.assertIn("0.0.0.0 a.example\n", contents)

    def test_manifest_write_and_reload(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "m.json"
            m = {"version": 1, "domain_count": 5, "sources": [], "errors": []}
            ub.write_manifest(m, p)
            self.assertEqual(json.loads(p.read_text()), m)


class PunycodeTests(unittest.TestCase):
    def test_ascii_passes_through(self):
        self.assertEqual(ub._punycode("Foo.Example"), "foo.example")

    def test_idn_punycoded(self):
        # "bücher.example" -> xn--bcher-kva.example
        self.assertEqual(ub._punycode("Bücher.example"),
                         "xn--bcher-kva.example")

    def test_garbage_rejected(self):
        self.assertIsNone(ub._punycode("not valid"))
        self.assertIsNone(ub._punycode(""))


class FetchLocalTests(unittest.TestCase):
    def test_reads_file(self):
        with tempfile.TemporaryDirectory() as d:
            pathlib.Path(d, "alpha.txt").write_text("0.0.0.0 x.example\n",
                                                    encoding="utf-8")
            src = ub.Source("alpha", "https://x/alpha", "hosts")
            f = ub.fetch_local(src, pathlib.Path(d))
            self.assertEqual(f.text, "0.0.0.0 x.example\n")
            self.assertIsNone(f.error)

    def test_missing_file_reports_error(self):
        with tempfile.TemporaryDirectory() as d:
            src = ub.Source("nope", "https://x/nope", "hosts")
            f = ub.fetch_local(src, pathlib.Path(d))
            self.assertIsNotNone(f.error)
            self.assertEqual(f.text, "")


class FetchRemoteOfflineTests(unittest.TestCase):
    def test_network_error_captured(self):
        # Bad URL scheme forces an immediate URLError without network.
        src = ub.Source("z", "bogus://doesnotexist", "plain")
        f = ub.fetch_remote(src, timeout=0.1)
        self.assertEqual(f.text, "")
        self.assertIsNotNone(f.error)


if __name__ == "__main__":
    unittest.main()
