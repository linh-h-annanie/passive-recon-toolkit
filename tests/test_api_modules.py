import json
import os
import re
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = next(p for p in Path(__file__).resolve().parents if (p / "modules").is_dir())
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests  # noqa: E402
from core import merger  # noqa: E402
from modules import apivoid_mod, ipinfo_mod  # noqa: E402

FAKE_KEY = "FAKEKEY0123456789abcdef"


# ----------------------------------------------------------------------------- fakes
class FakeResponse:
    def __init__(self, status=200, body=None, headers=None, raw=None):
        self.status_code = status
        self.headers = headers or {}
        self._raw = raw if raw is not None else json.dumps(body if body is not None else {}).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self):
        pass

    def iter_content(self, size):
        for i in range(0, len(self._raw), size):
            yield self._raw[i:i + size]

    @property
    def content(self):
        return self._raw

    def json(self):
        return json.loads(self._raw)

    @property
    def text(self):
        return self._raw.decode(errors="replace")

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code), response=self)


def strict_post(responses, calls):
    """Mimic requests.post: a non-numeric timeout is rejected, every call is recorded."""
    queue = list(responses)

    def post(url, **kwargs):
        timeout = kwargs.get("timeout")
        if not isinstance(timeout, (int, float, tuple)):
            raise TypeError(f"invalid timeout {timeout!r}")
        calls.append((url, kwargs))
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(item, Exception):
            raise item
        return item
    return post


GOOD_APIVOID = {"ip": "8.8.8.8", "blacklists": {"detections": 0, "engines_count": 78},
                "anonymity": {"is_vpn": False, "is_proxy": False, "is_tor": False, "is_hosting": False},
                "asn": {"asn": "AS3356", "org": "Level 3 Parent, LLC"}, "risk_score": {"result": 0}}


def fake_ipinfo(details=None, error=None):
    module = types.ModuleType("ipinfo")
    calls = []

    class Handler:
        def getDetails(self, ip):
            calls.append(ip)
            if error:
                raise error
            return types.SimpleNamespace(all=details)

    module.getHandler = lambda token, **kw: Handler()
    module.calls = calls
    return module


class HttpError(Exception):
    def __init__(self, status, message="boom"):
        super().__init__(message)
        self.response = types.SimpleNamespace(status_code=status, headers={})


ENV = {"IPINFO_TOKEN": FAKE_KEY, "APIVOID_API_KEY": FAKE_KEY}


# ----------------------------------------------------------------------------- IPinfo
class IpinfoTests(unittest.TestCase):
    def run_with(self, target, fake, config=None, env=ENV):
        with mock.patch.dict(sys.modules, {"ipinfo": fake}), mock.patch.dict(os.environ, env):
            return ipinfo_mod.run(target, config if config is not None else {})

    def test_run_accepts_config_dict_like_main_py(self):
        fake = fake_ipinfo({"ip": "8.8.8.8", "city": "Mountain View", "country": "US", "org": "AS15169 Google LLC"})
        result = self.run_with("8.8.8.8", fake, {})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["data"]["city"], "Mountain View")
        self.assertIn("timestamp", result)

    def test_missing_token_is_skipped(self):
        fake = fake_ipinfo({"ip": "8.8.8.8"})
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IPINFO_TOKEN", None)
            with mock.patch.dict(sys.modules, {"ipinfo": fake}):
                result = ipinfo_mod.run("8.8.8.8", {})
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(fake.calls, [])

    def test_bad_targets_never_reach_the_api(self):
        fake = fake_ipinfo({"ip": "x"})
        for bad in ("", "   ", "https://8.8.8.8/x", "10.0.0.1", "127.0.0.1", "8.8.8.8\n1.1.1.1", None):
            result = self.run_with(bad, fake, {})
            self.assertIn(result["status"], ("error", "skipped"), bad)
        self.assertEqual(fake.calls, [])

    def test_timeout_rate_limit_and_auth_are_distinguished(self):
        cases = [(requests.Timeout("slow"), "timeout"), (HttpError(429), "rate_limited"), (HttpError(401), "auth_error")]
        for error, reason in cases:
            result = self.run_with("8.8.8.8", fake_ipinfo(error=error), {})
            self.assertEqual(result["status"], "error")
            self.assertEqual(result["data"].get("reason"), reason)

    def test_empty_answer_is_not_reported_as_data(self):
        result = self.run_with("8.8.8.8", fake_ipinfo({"ip": "8.8.8.8"}), {})
        self.assertEqual(result["data"].get("reason"), "empty")

    def test_token_never_appears_in_output(self):
        result = self.run_with("8.8.8.8", fake_ipinfo(error=Exception(f"401 for token {FAKE_KEY}")), {})
        self.assertNotIn(FAKE_KEY, json.dumps(result))

    def test_domain_target_is_skipped_without_resolving_it(self):
        fake = fake_ipinfo({"ip": "93.184.216.34", "city": "X"})
        result = self.run_with("example.com", fake, {})  # any DNS lookup would trip the offline guard
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["data"].get("reason"), "needs_ip")
        self.assertEqual(fake.calls, [])

    def test_result_keeps_the_six_key_contract(self):
        result = self.run_with("8.8.8.8", fake_ipinfo({"ip": "8.8.8.8", "city": "X"}), {})
        self.assertEqual(set(result), {"module", "status", "source", "data", "error", "timestamp"})


# ----------------------------------------------------------------------------- APIVoid
class ApivoidTests(unittest.TestCase):
    def call(self, target, responses, config=None, env=ENV, cwd=None):
        calls = []
        old = os.getcwd()
        if cwd:
            os.chdir(cwd)  # the original module looked for its sample file relative to the working directory
        try:
            with mock.patch("requests.post", strict_post(responses, calls)), mock.patch.dict(os.environ, env), \
                    mock.patch("time.sleep"):
                result = apivoid_mod.run(target, config if config is not None else {})
        finally:
            os.chdir(old)
        return result, calls

    def test_success_with_config_dict(self):
        result, calls = self.call("8.8.8.8", [FakeResponse(200, GOOD_APIVOID)])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["data"]["detections"], 0)
        self.assertEqual(result["data"]["engines_count"], 78)
        self.assertEqual(len(calls), 1)
        self.assertIn("timestamp", result)

    def test_network_failure_is_error_never_silent_sample_data(self):
        result, _ = self.call("1.1.1.1", [requests.ConnectionError("down")], cwd=ROOT / "output")
        self.assertEqual(result["status"], "error")
        self.assertNotIn("risk_score", result["data"])  # no sample/cached numbers may stand in for a failed live call
        self.assertNotIn("offline_cached", json.dumps(result))

    def test_demo_mode_is_explicit_labelled_and_offline(self):
        result, calls = self.call("1.1.1.1", [FakeResponse(200, GOOD_APIVOID)], {"apivoid_mode": "demo"})
        self.assertEqual(calls, [])
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["data"].get("demo"))
        self.assertIn("DEMO", result["source"].upper())
        self.assertEqual(result["data"]["ip"], "8.8.8.8")  # the sample describes 8.8.8.8, never the requested target
        self.assertEqual(result["data"].get("requested_target"), "1.1.1.1")

    def test_rate_limit_is_reported_and_not_retried(self):
        result, calls = self.call("8.8.8.8", [FakeResponse(429, {}, {"Retry-After": "30"})])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["data"].get("reason"), "rate_limited")
        self.assertEqual(result["data"].get("retry_after_seconds"), 30)
        self.assertEqual(len(calls), 1)

    def test_auth_error_is_not_retried(self):
        for code in (401, 403):
            result, calls = self.call("8.8.8.8", [FakeResponse(code, {})])
            self.assertEqual(result["data"].get("reason"), "auth_error")
            self.assertEqual(len(calls), 1)

    def test_server_error_retried_once(self):
        result, calls = self.call("8.8.8.8", [FakeResponse(500, {}), FakeResponse(200, GOOD_APIVOID)])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(calls), 2)
        result, calls = self.call("8.8.8.8", [FakeResponse(503, {})])
        self.assertEqual(result["status"], "error")
        self.assertEqual(len(calls), 2)

    def test_timeout_is_distinguished(self):
        result, _ = self.call("8.8.8.8", [requests.Timeout("slow")])
        self.assertEqual(result["data"].get("reason"), "timeout")

    def test_not_json_and_wrong_shape_are_errors(self):
        for raw in (b"<html>oops</html>", b"[1, 2, 3]", b""):
            result, _ = self.call("8.8.8.8", [FakeResponse(200, raw=raw)])
            self.assertEqual(result["status"], "error", raw)
            self.assertEqual(result["data"].get("reason"), "bad_response")

    def test_missing_fields_stay_unknown_not_false(self):
        result, _ = self.call("8.8.8.8", [FakeResponse(200, {"ip": "8.8.8.8", "anonymity": None, "risk_score": None})])
        self.assertEqual(result["status"], "ok")
        self.assertIsNone(result["data"]["is_vpn"])
        self.assertIsNone(result["data"]["risk_score"])

    def test_oversized_response_rejected(self):
        result, _ = self.call("8.8.8.8", [FakeResponse(200, raw=b"{" + b" " * (2 * 1024 * 1024) + b"}")])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["data"].get("reason"), "bad_response")

    def test_key_never_appears_in_output_and_redirects_are_not_followed(self):
        result, calls = self.call("8.8.8.8", [Exception(f"failure with {FAKE_KEY} inside")])
        self.assertNotIn(FAKE_KEY, json.dumps(result))
        self.assertIs(calls[0][1].get("allow_redirects"), False)
        self.assertNotIn(FAKE_KEY, calls[0][0])  # the key travels in a header, never in the URL

    def test_bad_targets_never_reach_the_api(self):
        for bad in ("", "example.com", "https://8.8.8.8", "10.0.0.1", "8.8.8.8:80", None):
            result, calls = self.call(bad, [FakeResponse(200, GOOD_APIVOID)])
            self.assertIn(result["status"], ("error", "skipped"), bad)
            self.assertEqual(calls, [], bad)

    def test_result_keeps_the_six_key_contract(self):
        result, _ = self.call("8.8.8.8", [FakeResponse(200, GOOD_APIVOID)])
        self.assertEqual(set(result), {"module", "status", "source", "data", "error", "timestamp"})

    def test_missing_key_is_skipped(self):
        env = {k: v for k, v in os.environ.items() if k != "APIVOID_API_KEY"}
        with mock.patch.dict(os.environ, env, clear=True):
            calls = []
            with mock.patch("requests.post", strict_post([FakeResponse(200, GOOD_APIVOID)], calls)):
                result = apivoid_mod.run("8.8.8.8", {})
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(calls, [])


# ----------------------------------------------------------------------------- merger wording (honesty)
class MergerHonestyTests(unittest.TestCase):
    def merged(self):
        shodan = {"status": "ok", "source": "Shodan", "data": {
            "hosts": [{"ip": "93.184.216.34", "ports": [22], "vulns": ["CVE-2020-0001"]}],
            "services": [{"ip": "93.184.216.34", "port": 22, "transport": "tcp", "service": "ssh"}]}}
        return merger.merge_shodan_censys(shodan, {"status": "skipped"})

    def test_warnings_do_not_claim_open_ports_or_confirmed_vulnerabilities(self):
        text = " ".join(self.merged()["warnings"]).lower()
        self.assertNotIn("exposed", text)
        self.assertIn("unverified", text)
        self.assertNotIn("has 1 known cve", text)

    def test_bad_port_value_does_not_crash_the_merge(self):
        bad = {"status": "ok", "source": "Shodan", "data": {"services": [
            {"ip": "1.1.1.1", "port": "abc"}, {"ip": "1.1.1.1", "port": 80}]}}
        merged = merger.merge_shodan_censys(bad, {"status": "skipped"})
        self.assertEqual([s["port"] for s in merged["services"]], [80])


# ----------------------------------------------------------------------------- repository hygiene
class RepositoryHygieneTests(unittest.TestCase):
    def text_files(self):
        for path in ROOT.rglob("*"):
            if path.is_file() and "vendor" not in path.parts and ".git" not in path.parts and path.suffix in (
                    ".py", ".md", ".txt", ".json", ".html", ".example", ".ini", ".toml", ".yml", ".yaml", ""):
                yield path

    def test_no_secret_file_is_shipped(self):
        names = [p.name.lower() for p in ROOT.rglob("*") if p.is_file()]
        self.assertFalse([n for n in names if "apikey" in n or n == ".env"], "secret file inside the project")

    def test_no_hardcoded_secret_assignments(self):
        pattern = re.compile(r"(api[_-]?key|token|secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]", re.I)
        found = []
        for path in self.text_files():
            if path.name.endswith(".example") or path.name == "test_review_fixes.py":
                continue
            for match in pattern.finditer(path.read_text(encoding="utf-8", errors="ignore")):
                found.append((path.name, match.group(1)))
        self.assertEqual(found, [])

    def test_gitignore_and_env_example(self):
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn(".env", [line.strip() for line in gitignore])
        example = (ROOT / ".env.example").read_text(encoding="utf-8")
        for name in ("SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET", "IPINFO_TOKEN", "APIVOID_API_KEY"):
            self.assertIn(name + "=", example)
        self.assertNotRegex(example, r"=\s*[A-Za-z0-9]{24,}\s*$")

    def test_tests_directory_has_no_live_scripts(self):
        for path in (ROOT / "tests").glob("*.py"):
            source = path.read_text(encoding="utf-8")
            if path.name == "test_review_fixes.py":
                continue
            self.assertNotRegex(source, r"(?m)^exit\(", path.name)  # a script that exits at import breaks discovery
            self.assertNotIn("requests.post(url", source, path.name)
            self.assertNotIn("ipinfo.getHandler(token)", source, path.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
