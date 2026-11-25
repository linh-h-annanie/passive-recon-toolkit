"""Deterministic tests for Linh's three modules (no network, no API keys).

Run from the repository root:  python -m unittest discover -s tests -v
"""
import json
import sys
import time
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "modules").is_dir())
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests  # noqa: E402
from modules import crtsh_mod, dns_mod, whois_mod  # noqa: E402

NOW = datetime(2026, 11, 23, tzinfo=timezone.utc)


class Entry(dict):  # behaves like python-whois WhoisEntry: a dict subclass with extra attributes
    def __init__(self, domain, text):
        super().__init__()
        self.domain = domain
        self.text = text


class FakeResponse:
    def __init__(self, body=b"[]", status=200):
        self.body, self.status_code = body, status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}", response=self)

    def iter_content(self, size):
        for i in range(0, len(self.body), size):
            yield self.body[i:i + size]


def fake_dns_modules(answers):
    """answers: {record_type: list of text | error name}. Builds fake dns / dns.exception / dns.resolver modules."""
    class DNSException(Exception):
        pass

    class NoAnswer(DNSException):
        pass

    class NXDOMAIN(DNSException):
        pass

    class Answer:
        def __init__(self, text):
            self.text = text
            self.strings = [text.encode()] if text.startswith("v=") else None

        def to_text(self):
            return self.text

    class Resolver:
        timeout = lifetime = None

        def resolve(self, domain, record_type):
            value = answers.get(record_type, "NoAnswer")
            if isinstance(value, str):  # an error name: "NoAnswer", "NXDOMAIN" or "DNSException"
                raise {"NoAnswer": NoAnswer, "NXDOMAIN": NXDOMAIN, "DNSException": DNSException}[value]()
            return [Answer(v) for v in value]

    dns_pkg = types.ModuleType("dns")
    exc_mod = types.ModuleType("dns.exception")
    res_mod = types.ModuleType("dns.resolver")
    exc_mod.DNSException = DNSException
    res_mod.NoAnswer, res_mod.NXDOMAIN, res_mod.Resolver = NoAnswer, NXDOMAIN, Resolver
    dns_pkg.exception, dns_pkg.resolver = exc_mod, res_mod
    return {"dns": dns_pkg, "dns.exception": exc_mod, "dns.resolver": res_mod}, NoAnswer, NXDOMAIN, DNSException


class CommonTests(unittest.TestCase):
    def test_signature_matches_main(self):
        for module in (whois_mod, dns_mod, crtsh_mod):
            self.assertIn(module.run("1.2.3.4", {})["module"], {"whois", "dns", "crtsh"})

    def test_invalid_domains(self):
        for module in (whois_mod, dns_mod, crtsh_mod):
            for bad in ("a b.com", "%", "x;rm.com", "localhost"):
                self.assertEqual(module.run(bad, {})["status"], "error", (module.__name__, bad))

    def test_every_result_has_contract_keys(self):
        for module in (whois_mod, dns_mod, crtsh_mod):
            result = module.run("%", {})
            for key in ("module", "status", "source", "data", "error", "timestamp"):
                self.assertIn(key, result)


class WhoisTests(unittest.TestCase):
    def test_dict_subclass_and_status(self):
        entry = Entry("example.com", "RAW")
        entry.update({"domain_name": ["EXAMPLE.COM", "example.com"], "registrar": "R", "creation_date": [datetime(1997, 9, 15), datetime(1998, 1, 1)], "expiration_date": datetime(2028, 9, 14), "name_servers": ["NS1.X.COM", "ns1.x.com"], "status": ["clientDeleteProhibited https://icann.org/epp#a"], "emails": ["abuse@x.com"]})
        with mock.patch.dict(sys.modules, {"whois": mock.Mock(whois=lambda domain: entry)}):
            result = whois_mod.run("https://Example.com/path", {})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["data"]["domain_name"], ["example.com"])
        self.assertEqual(result["data"]["status"], ["clientdeleteprohibited"])
        self.assertEqual(result["data"]["emails_masked"], ["a***@x.com"])
        self.assertTrue(result["data"]["creation_date"].startswith("1997-09-15"))

    def test_timeout_does_not_block(self):
        with mock.patch.dict(sys.modules, {"whois": mock.Mock(whois=lambda domain: time.sleep(3))}):
            started = time.time()
            result = whois_mod.run("example.com", {}, timeout=0.3)
        self.assertEqual(result["status"], "error")
        self.assertLess(time.time() - started, 1.5)

    def test_empty_is_error(self):
        with mock.patch.dict(sys.modules, {"whois": mock.Mock(whois=lambda domain: Entry(domain, ""))}):
            self.assertEqual(whois_mod.run("example.com", {})["status"], "error")

    def test_ip_is_skipped(self):
        self.assertEqual(whois_mod.run("8.8.8.8", {})["status"], "skipped")


class CrtshNormalizeTests(unittest.TestCase):
    def test_precert_and_cert_with_different_ids_are_one_certificate(self):
        row = {"name_value": "example.net", "not_before": "2026-09-26T23:41:19", "not_after": "2026-12-25T23:48:34", "issuer_name": "Cloudflare"}
        data = crtsh_mod.normalize_certs([dict(row, id=1), dict(row, id=2), dict(row, id=3, issuer_name="Other CA")], "example.net", now=NOW)
        self.assertEqual(data["total_certificates"], 2)
        self.assertEqual(data["duplicates_removed"], 1)

    def test_wildcard_apex_and_scope(self):
        raw = [{"id": 1, "name_value": "*.example.com\nwww.example.com\nevil.org", "not_before": "2026-10-01T00:00:00", "not_after": "2026-12-01T00:00:00", "issuer_name": "LE"},
               {"id": 2, "name_value": "old.example.com", "not_after": "2020-01-01T00:00:00"},
               {"id": 3, "name_value": "other.org\nanother.net", "not_after": "2027-01-01T00:00:00"}]
        data = crtsh_mod.normalize_certs(raw, "example.com", now=NOW)
        self.assertEqual(data["subdomains"], ["old.example.com", "www.example.com"])  # apex excluded
        self.assertEqual(data["total_certificates"], 2)  # the out-of-scope row is not counted
        self.assertEqual(data["expired_certificates"], 1)
        self.assertEqual(len(data["expiring_within_30_days"]), 1)
        self.assertEqual(len(data["notes"]), 1)

    def test_error_not_raised(self):
        with mock.patch.object(crtsh_mod, "request_certificates", side_effect=RuntimeError("502")):
            self.assertEqual(crtsh_mod.run("example.com", {})["status"], "error")


class CrtshRequestTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(crtsh_mod.time, "sleep")
        self.sleep = patcher.start()
        self.addCleanup(patcher.stop)

    def test_retries_timeout_then_succeeds(self):
        calls = [requests.Timeout("slow"), FakeResponse(json.dumps([{"id": 1}]).encode())]
        with mock.patch("requests.get", side_effect=calls) as get:
            self.assertEqual(crtsh_mod.request_certificates("example.com"), [{"id": 1}])
        self.assertEqual(get.call_count, 2)

    def test_retries_html_error_page(self):
        with mock.patch("requests.get", side_effect=[FakeResponse(b"<html>busy</html>"), FakeResponse(b"[]")]):
            self.assertEqual(crtsh_mod.request_certificates("example.com"), [])

    def test_crtsh_404_is_retried(self):
        with mock.patch("requests.get", return_value=FakeResponse(b"", 404)) as get:
            with self.assertRaises(requests.HTTPError):
                crtsh_mod.request_certificates("example.com", attempts=3)
        self.assertEqual(get.call_count, 3)
        self.assertEqual(self.sleep.call_count, 2)

    def test_gives_up_after_all_attempts(self):
        with mock.patch("requests.get", side_effect=requests.Timeout("slow")) as get:
            result = crtsh_mod.run("example.org", {})
        self.assertEqual(get.call_count, 3)
        self.assertEqual(result["status"], "error")

    def test_oversized_response_is_rejected(self):
        with mock.patch("requests.get", return_value=FakeResponse(b"[" + b"1," * 100 + b"1]")):
            with self.assertRaises(crtsh_mod.ResponseTooLarge):
                crtsh_mod.request_certificates("example.com", max_bytes=50)


class DnsTests(unittest.TestCase):
    def test_ip_input_reverse_timeout(self):
        with mock.patch("socket.gethostbyaddr", side_effect=lambda ip: time.sleep(3)):
            started = time.time()
            result = dns_mod.run("8.8.8.8", {})
        self.assertLess(time.time() - started, 4.5)
        self.assertEqual(result["data"]["reverse"], {"8.8.8.8": None})

    def test_private_ip_is_skipped_and_never_resolved(self):
        with mock.patch("socket.gethostbyaddr") as lookup:
            for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.1.1"):
                self.assertEqual(dns_mod.run(ip, {})["status"], "skipped")
            self.assertIsNone(dns_mod.reverse_lookup("10.0.0.5"))
        lookup.assert_not_called()

    def test_txt_join(self):
        answer = mock.Mock(strings=[b"v=spf1 ", b"include:x.com ~all"])
        self.assertEqual(dns_mod.txt_text(answer), "v=spf1 include:x.com ~all")

    def test_domain_run_missing_types_are_not_errors(self):
        modules, *_ = fake_dns_modules({"A": ["93.184.216.34", "10.0.0.9"], "NS": ["ns1.example.net."], "TXT": ["v=spf1 -all"]})
        with mock.patch.dict(sys.modules, modules), mock.patch("socket.gethostbyaddr", return_value=("host.example", [], [])):
            result = dns_mod.run("Example.NET", {})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["data"]["notes"], [])  # NoAnswer is normal, not a failure
        self.assertEqual(result["data"]["records"]["A"], ["93.184.216.34", "10.0.0.9"])
        self.assertEqual(result["data"]["records"]["TXT"], ["v=spf1 -all"])
        self.assertEqual(result["data"]["reverse"], {"93.184.216.34": "host.example", "10.0.0.9": None})  # private IP never resolved

    def test_domain_run_real_failure_is_noted(self):
        modules, *_ = fake_dns_modules({"A": ["93.184.216.34"], "MX": "DNSException"})
        with mock.patch.dict(sys.modules, modules), mock.patch("socket.gethostbyaddr", side_effect=OSError):
            result = dns_mod.run("example.net", {})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["data"]["notes"], ["MX query failed"])

    def test_nxdomain_everywhere_is_error(self):
        modules, *_ = fake_dns_modules({t: "NXDOMAIN" for t in dns_mod.RECORD_TYPES})
        with mock.patch.dict(sys.modules, modules):
            result = dns_mod.run("does-not-exist.example", {})
        self.assertEqual(result["status"], "error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
