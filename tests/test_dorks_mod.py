"""Kiểm thử chạy thật bằng unittest, Google và kết quả đều được mock."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from modules import dorks_mod as mod
from modules import google_search_client as client


class DorksTests(unittest.TestCase):
    def test_valid_domain_and_url(self):
        for value in ("EXAMPLE.ORG.", "https://example.org/docs?q=a"):
            self.assertEqual(mod.clean_domain(value), "example.org")

    def test_invalid_domain(self):
        for value in ("bad domain", "example.org OR site:other.org", "-bad.org",
                      "localhost", "a..org", "ftp://example.org", "https://user@example.org",
                      "example.org:443", "foo.123", "x" * 64 + ".org"):
            with self.subTest(value=value):
                self.assertEqual(mod.run(value)["status"], "error")

    def test_empty(self):
        for value in ("", "  ", None, 123):
            self.assertEqual(mod.run(value)["status"], "error")

    def test_ip_skipped(self):
        for value in ("8.8.8.8", "2001:db8::1", "https://8.8.8.8/"):
            self.assertEqual(mod.run(value)["status"], "skipped")

    def test_disabled_does_not_search(self):
        with patch.object(mod, "execute_live") as search:
            self.assertEqual(mod.run("example.org")["status"], "skipped")
            search.assert_not_called()

    def test_idna(self):
        self.assertEqual(mod.clean_domain("bücher.de"), "xn--bcher-kva.de")

    def test_control_characters_rejected(self):
        for value in ("exam\nple.org", "exam\tple.org", "example.org\x00", "example.org\x7f"):
            self.assertEqual(mod.run(value)["status"], "error")
        self.assertEqual(mod.normalize_urls(["https://example.org/a\x00"], "example.org"), [])

    def test_success_and_delay(self):
        with patch.object(client, "search", return_value=["https://example.org/docs"]), \
                patch.object(mod.time, "sleep") as sleep:
            outcome = mod.collect("example.org", "google")
        self.assertEqual(outcome["status"], "ok")
        self.assertEqual(len(outcome["data"]["queries"]), 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertTrue(all(10 <= c.args[0] <= 15 for c in sleep.call_args_list))

    def test_empty_results(self):
        with patch.object(client, "search", return_value=[]), patch.object(mod.time, "sleep"):
            outcome = mod.collect("example.org", "google")
        self.assertEqual(outcome["status"], "ok")
        self.assertEqual(outcome["data"]["urls"], [])

    def test_scope_duplicates_and_fragment(self):
        urls = ["https://EXAMPLE.ORG/docs#one", "https://example.org/docs#two",
                "https://sub.example.org/", "https://example.org.evil.test/",
                "https://evil-example.org/", "javascript:alert(1)", "https://u:p@example.org/",
                "https://example.org:bad/", None]
        self.assertEqual(mod.normalize_urls(urls, "example.org"),
                         ["https://example.org/docs", "https://sub.example.org/"])

    def test_http_errors_stop_without_retry(self):
        for code in (429, 403, 302, 503):
            with self.subTest(code=code):
                error = HTTPError("https://www.google.com/search", code, "blocked", {}, None)
                opener = MagicMock()
                opener.open.side_effect = error
                with patch.object(client, "build_opener", return_value=opener), \
                        patch.object(mod.time, "sleep") as sleep:
                    outcome = mod.collect("example.org", "google")
                self.assertEqual(outcome["status"], "error")
                self.assertIn(f"http_{code}", outcome["error"])
                self.assertEqual(opener.open.call_count, 1)
                sleep.assert_not_called()

    def test_connection_error(self):
        opener = MagicMock()
        opener.open.side_effect = URLError("network down")
        with patch.object(client, "build_opener", return_value=opener):
            with self.assertRaisesRegex(client.SearchError, "connection_error"):
                client.search("site:example.org")

    def test_socket_timeout(self):
        opener = MagicMock()
        opener.open.side_effect = TimeoutError()
        with patch.object(client, "build_opener", return_value=opener):
            with self.assertRaisesRegex(client.SearchError, "timeout"):
                client.search("site:example.org")

    def test_wrapped_socket_timeout(self):
        opener = MagicMock()
        opener.open.side_effect = URLError(TimeoutError("timed out"))
        with patch.object(client, "build_opener", return_value=opener):
            with self.assertRaisesRegex(client.SearchError, "^timeout:"):
                client.search("site:example.org")

    def test_response_size_limit(self):
        response = MagicMock()
        response.read.return_value = b"x" * (client.MAX_BYTES + 1)
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(client, "build_opener", return_value=opener):
            with self.assertRaisesRegex(client.SearchError, "response_too_large"):
                client.search("site:example.org")

    def test_worker_deadline(self):
        with patch.object(mod.subprocess, "run", side_effect=subprocess.TimeoutExpired("worker", 65)):
            self.assertIn("65", mod.execute_live("example.org", "pagodo")["error"])

    def test_partial_result_on_error(self):
        with patch.object(client, "search", side_effect=[["https://example.org/docs"], client.SearchError("blocked")]), \
                patch.object(mod.time, "sleep"):
            outcome = mod.collect("example.org", "google")
        self.assertEqual(outcome["status"], "error")
        self.assertEqual(outcome["data"]["urls"], ["https://example.org/docs"])
        self.assertEqual(len(outcome["data"]["queries"]), 2)

    def test_real_pagodo_with_mock_transport(self):
        # Chạy code Pagodo thật; chỉ hàm mạng được mock.
        with patch.object(client, "search", return_value=["https://example.org/guide"]):
            self.assertEqual(mod.pagodo_search("example.org", mod.QUERIES[0]), ["https://example.org/guide"])

    def test_pagodo_system_exit_does_not_escape(self):
        fake_module = MagicMock()
        fake_module.Pagodo.side_effect = SystemExit(1)
        with patch.object(mod.importlib.util, "module_from_spec", return_value=fake_module), \
                patch.object(mod.importlib.util, "spec_from_file_location"):
            with self.assertRaisesRegex(client.SearchError, "pagodo_exit"):
                mod.pagodo_search("example.org", mod.QUERIES[0])

    def test_pagodo_restores_logger(self):
        import logging
        logger = logging.getLogger("pagodo")
        previous_level, previous_handlers = logger.level, list(logger.handlers)
        with patch.object(client, "search", return_value=[]):
            mod.pagodo_search("example.org", mod.QUERIES[0])
        self.assertEqual(logger.level, previous_level)
        self.assertEqual(logger.handlers, previous_handlers)

    def test_pagodo_does_not_hide_errors(self):
        with patch.object(client, "search", side_effect=client.SearchError("http_429")) as search, \
                patch.object(mod.time, "sleep") as sleep:
            outcome = mod.collect("example.org", "pagodo")
        self.assertEqual(outcome["status"], "error")
        self.assertIn("http_429", outcome["error"])
        self.assertEqual(search.call_count, 1)
        sleep.assert_not_called()

    def test_parser_success(self):
        html = '<a href="/url?q=https%3A%2F%2Fexample.org%2Fdocs"><h3>Docs</h3></a>'
        self.assertEqual(client.parse_results(html), ["https://example.org/docs"])

    def test_parser_empty(self):
        self.assertEqual(client.parse_results("Your search did not match any documents"), [])

    def test_parser_absolute_google_redirect(self):
        html = '<a href="https://www.google.com/url?q=https%3A%2F%2Fexample.org%2Fdocs"><h3>Docs</h3></a>'
        self.assertEqual(client.parse_results(html), ["https://example.org/docs"])

    def test_parser_ignores_broken_link(self):
        html = '<a href="https://[bad"><h3>Bad</h3></a><a href="https://example.org/docs"><h3>Docs</h3></a>'
        self.assertEqual(client.parse_results(html), ["https://example.org/docs"])

    def test_worker_failure_is_error(self):
        with patch.object(mod.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
            self.assertEqual(mod.execute_live("example.org", "pagodo")["status"], "error")

    def test_parser_blocked_and_unknown(self):
        for html in ("unusual traffic", "g-recaptcha", "Before you continue to Google", "<html>new layout</html>"):
            with self.assertRaises(client.SearchError):
                client.parse_results(html)

    def test_single_request_no_target_fetching(self):
        response = MagicMock()
        response.read.return_value = b'<a href="https://example.org/docs"><h3>Docs</h3></a>'
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(client, "build_opener", return_value=opener):
            self.assertEqual(client.search("site:example.org"), ["https://example.org/docs"])
        opener.open.assert_called_once()
        request = opener.open.call_args.args[0]
        self.assertTrue(request.full_url.startswith("https://www.google.com/search?"))
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 8)

    def test_output_schema_and_json(self):
        outcome = mod.run("example.org", {"dorks_mode": "demo"})
        self.assertTrue({"module", "status", "source", "data", "error"} <= outcome.keys())
        self.assertEqual(json.loads(json.dumps(outcome)), outcome)
        self.assertEqual(outcome["data"]["mode"], "demo")

    def test_main_style_contract(self):
        # Chỉ kiểm tra giao diện main dự kiến gọi, repo chưa có main.py thật.
        from modules.dorks_mod import run
        results = [run("example.org", config={"dorks_mode": "demo"})]
        self.assertEqual(results[0]["module"], "dorks")

    def test_cli_demo_and_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "demo.json"
            command = [sys.executable, "-m", "modules.dorks_mod", "--target", "example.org"]
            first = subprocess.run(command + ["--mode", "demo", "--output", str(output)],
                                   cwd=mod.ROOT, capture_output=True, timeout=10)
            self.assertEqual(first.returncode, 0, first.stderr)
            saved = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(saved["data"]["mode"], "demo")
            replay = subprocess.run(command + ["--replay", str(output)], cwd=mod.ROOT,
                                    capture_output=True, timeout=10)
            self.assertEqual(replay.returncode, 0, replay.stderr)
            self.assertTrue(json.loads(replay.stdout)["data"]["replayed"])


if __name__ == "__main__":
    unittest.main()
