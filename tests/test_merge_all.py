import unittest

from core.merger import merge_all


def res(module, status, data=None, error=None):
    return {"module": module, "status": status, "source": module,
            "data": data or {}, "error": error, "timestamp": "2026-11-27T00:00:00+00:00"}


class MergeAllTests(unittest.TestCase):
    def test_groups_by_status_and_warns_on_expiry(self):
        merged = merge_all("example.com", [
            res("whois", "ok", {"days_to_expiry": 10}),
            res("shodan", "skipped", error="Missing SHODAN_API_KEY"),
            res("dns", "error", error="timeout"),
        ])
        self.assertEqual(merged["summary"]["ok"], ["whois"])
        self.assertEqual(merged["summary"]["skipped"][0]["module"], "shodan")
        self.assertEqual(merged["summary"]["error"][0]["module"], "dns")
        self.assertTrue(any("expires" in w for w in merged["warnings"]))

    def test_ignores_non_dict_results(self):
        merged = merge_all("example.com", [None, "x", res("whois", "ok", {"registrar": "R"})])
        self.assertEqual(merged["summary"]["ok"], ["whois"])

    def test_includes_shodan_network_and_risky_port_warning(self):
        shodan = res("shodan", "ok", {
            "hosts": [],
            "services": [{"ip": "1.1.1.1", "port": 22, "transport": "tcp", "service": "ssh"}],
        })
        merged = merge_all("1.1.1.1", [shodan])
        self.assertEqual(len(merged["network"]["services"]), 1)
        self.assertTrue(any("22/tcp" in w for w in merged["warnings"]))

    def test_keeps_partial_data_on_error_and_flags_demo(self):
        merged = merge_all("example.org", [
            res("dorks", "error", {"urls": ["https://example.org/a"], "mode": "demo"}, "http_429"),
        ])
        self.assertTrue(merged["summary"]["error"][0]["partial_data"])
        self.assertEqual(merged["modules"]["dorks"]["urls"], ["https://example.org/a"])
        self.assertTrue(any("DEMO" in w for w in merged["warnings"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)