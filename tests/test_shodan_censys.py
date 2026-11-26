import unittest
from unittest.mock import patch

from core.merger import merge_shodan_censys
from modules import censys_mod, shodan_mod

CONTRACT_KEYS = {"module", "status", "source", "data", "error", "timestamp"}


class ShodanCensysTests(unittest.TestCase):
    def test_shodan_missing_key_returns_skipped(self):
        with patch.object(shodan_mod, "load_env_key", return_value=""):
            res = shodan_mod.run("104.20.23.154")
        self.assertEqual(CONTRACT_KEYS, set(res.keys()))
        self.assertEqual("skipped", res["status"])

    def test_censys_missing_key_returns_skipped(self):
        with patch.object(censys_mod, "load_env_key", return_value=""):
            res = censys_mod.run("104.20.23.154")
        self.assertEqual(CONTRACT_KEYS, set(res.keys()))
        self.assertEqual("skipped", res["status"])

    def test_private_ip_is_skipped(self):
        with patch.object(shodan_mod, "load_env_key", return_value="dummy-key"):
            res = shodan_mod.run("192.168.1.10")
        self.assertEqual("skipped", res["status"])

    def test_shodan_run_and_normalize(self):
        sample_raw = {
            "org": "Cloudflare, Inc.",
            "isp": "Cloudflare, Inc.",
            "asn": "AS13335",
            "country_name": "United States",
            "city": "San Francisco",
            "ports": [80, 443],
            "vulns": {"CVE-2024-0001": {}},
            "data": [
                {"port": 443, "transport": "tcp", "product": "Cloudflare HTTP", "data": "HTTP/1.1 200 OK"},
            ],
        }
        with patch.object(shodan_mod, "load_env_key", return_value="dummy-key"), \
             patch.object(shodan_mod, "_fetch_shodan_host", return_value=sample_raw):
            res = shodan_mod.run(["104.20.23.154"])
        self.assertEqual("ok", res["status"])
        self.assertEqual(1, res["data"]["total_services"])
        self.assertEqual(443, res["data"]["services"][0]["port"])

    def test_censys_run_and_normalize(self):
        sample_raw = {
            "autonomous_system": {"asn": 13335, "name": "CLOUDFLARENET"},
            "location": {"country": "United States", "city": "San Francisco"},
            "services": [
                {"port": 443, "transport_protocol": "TCP", "service_name": "HTTPS", "banner": "TLSv1.3"},
                {"port": 80, "transport_protocol": "TCP", "service_name": "HTTP", "banner": "301 Moved"},
            ],
        }
        with patch.object(censys_mod, "load_env_key", return_value="dummy-token"), \
             patch.object(censys_mod, "_fetch_censys_v3", return_value=sample_raw):
            res = censys_mod.run(["104.20.23.154"])
        self.assertEqual("ok", res["status"])
        self.assertEqual(2, res["data"]["total_services"])

    def test_merger_deduplicates_and_flags_risky_ports(self):
        s_res = {
            "status": "ok",
            "source": "Shodan",
            "data": {
                "hosts": [{"ip": "1.1.1.1", "org": "TestOrg", "ports": [22, 443], "vulns": []}],
                "services": [
                    {"ip": "1.1.1.1", "port": 443, "transport": "tcp", "service": "https", "source": "Shodan"},
                    {"ip": "1.1.1.1", "port": 22, "transport": "tcp", "service": "ssh", "source": "Shodan"},
                ],
            },
        }
        c_res = {
            "status": "ok",
            "source": "Censys",
            "data": {
                "hosts": [{"ip": "1.1.1.1", "asn": "AS13335", "ports": [443], "vulns": []}],
                "services": [
                    {"ip": "1.1.1.1", "port": 443, "transport": "tcp", "service": "HTTPS", "source": "Censys"},
                ],
            },
        }
        merged = merge_shodan_censys(s_res, c_res)
        self.assertEqual(2, len(merged["services"]))
        port_443 = [s for s in merged["services"] if s["port"] == 443][0]
        self.assertEqual("Shodan, Censys", port_443["source"])
        self.assertTrue(any("22/tcp (SSH)" in w for w in merged["warnings"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
