import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import crtsh_mod, dns_mod, whois_mod


class Entry(dict):
    def __init__(self, domain, text):
        super().__init__()
        self.domain = domain
        self.text = text


NOW = datetime(2026, 11, 23, tzinfo=timezone.utc)


class LinhModuleTests(unittest.TestCase):
    def test_signature_matches_main(self):
        for module in (whois_mod, dns_mod, crtsh_mod):
            self.assertIn(module.run("1.2.3.4", {})["module"], {"whois", "dns", "crtsh"})

    def test_whois_dict_subclass_and_status(self):
        entry = Entry("example.com", "RAW")
        entry.update({"domain_name": ["EXAMPLE.COM", "example.com"], "registrar": "R", "creation_date": [datetime(1997, 9, 15), datetime(1998, 1, 1)], "expiration_date": datetime(2028, 9, 14), "name_servers": ["NS1.X.COM", "ns1.x.com"], "status": ["clientDeleteProhibited https://icann.org/epp#a"], "emails": ["abuse@x.com"]})
        fake = mock.Mock(whois=lambda domain: entry)
        with mock.patch.dict(sys.modules, {"whois": fake}):
            result = whois_mod.run("https://Example.com/path", {})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["data"]["domain_name"], ["example.com"])
        self.assertEqual(result["data"]["status"], ["clientdeleteprohibited"])
        self.assertEqual(result["data"]["emails_masked"], ["a***@x.com"])

    def test_whois_timeout_does_not_block(self):
        fake = mock.Mock(whois=lambda domain: time.sleep(3))
        with mock.patch.dict(sys.modules, {"whois": fake}):
            started = time.time()
            result = whois_mod.run("example.com", {}, timeout=0.3)
        self.assertEqual(result["status"], "error")
        self.assertLess(time.time() - started, 1.5)

    def test_whois_empty_is_error(self):
        with mock.patch.dict(sys.modules, {"whois": mock.Mock(whois=lambda domain: Entry(domain, ""))}):
            self.assertEqual(whois_mod.run("example.com", {})["status"], "error")

    def test_invalid_domains(self):
        for module in (whois_mod, dns_mod, crtsh_mod):
            for bad in ("a b.com", "%", "x;rm.com", "localhost"):
                self.assertEqual(module.run(bad, {})["status"], "error")

    def test_crtsh_dedupe_wildcard_expiry(self):
        raw = [{"id": 1, "name_value": "*.example.com\nwww.example.com\nevil.org", "not_before": "2026-10-01T00:00:00", "not_after": "2026-12-01T00:00:00", "issuer_name": "LE"}, {"id": 1, "name_value": "www.example.com", "not_after": "2026-12-01T00:00:00"}, {"id": 2, "name_value": "old.example.com", "not_after": "2020-01-01T00:00:00"}]
        data = crtsh_mod.normalize_certs(raw, "example.com", now=NOW)
        self.assertEqual(data["total_certificates"], 2)
        self.assertEqual(data["subdomains"], ["example.com", "old.example.com", "www.example.com"])
        self.assertEqual(len(data["expiring_within_30_days"]), 1)
        self.assertEqual(data["expired_certificates"], 1)

    def test_crtsh_error_not_raised(self):
        with mock.patch.object(crtsh_mod, "request_certificates", side_effect=RuntimeError("502")):
            self.assertEqual(crtsh_mod.run("example.com", {})["status"], "error")

    def test_dns_ip_branch_and_reverse_timeout(self):
        with mock.patch("socket.gethostbyaddr", side_effect=lambda ip: time.sleep(3)):
            started = time.time()
            result = dns_mod.run("8.8.8.8", {})
        self.assertLess(time.time() - started, 4.5)
        self.assertEqual(result["data"]["reverse"], {"8.8.8.8": None})

    def test_dns_txt_join(self):
        answer = mock.Mock(strings=[b"v=spf1 ", b"include:x.com ~all"])
        self.assertEqual(dns_mod.txt_text(answer), "v=spf1 include:x.com ~all")


if __name__ == "__main__":
    unittest.main(verbosity=2)
