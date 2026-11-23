"""Offline checks: synthetic HTML is test data, never evidence of a live run."""
from contextlib import chdir
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, Mock
from uuid import uuid4

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import recon
from _worker import GoogleTransport, StopSearch, execute


class CoreTests(unittest.TestCase):
    def test_missing_dependency_has_explicit_status(self):
        with patch('_worker.GoogleTransport', side_effect=ModuleNotFoundError('requests')):
            result = execute({}, BASE / 'output')
        self.assertEqual(result['status'], 'dependency_error')
        self.assertEqual(result['urls'], [])

    def test_domain_validation(self):
        self.assertEqual(recon.normalize_domain('NASA.GOV.'), 'nasa.gov')
        for bad in ['https://nasa.gov', 'nasa.gov/path', 'nasa.gov:443', '127.0.0.1',
                    'x..gov', '-nasa.gov', 'nasa.gov OR evil.com']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                recon.normalize_domain(bad)

    def test_scope_cannot_be_split_by_expression(self):
        self.assertEqual(recon.build_query('nasa.gov', 'filetype:pdf "annual report"'),
                         'site:nasa.gov filetype:pdf "annual report"')
        for expr in ['site:evil.com', 'pdf OR docx', 'pdf|docx', '(pdf)', 'pdf\nword']:
            with self.subTest(expr=expr), self.assertRaises(ValueError):
                recon.build_query('nasa.gov', expr)

    def test_scope_filter_and_dedup(self):
        values = ['https://NASA.GOV/a.pdf#one', 'https://nasa.gov/a.pdf#two',
                  'https://ntrs.nasa.gov/b.pdf', 'https://notnasa.gov/x',
                  'https://nasa.gov.evil.com/x', 'https://nasa.gov@evil.com/x',
                  'javascript:alert(1)', 'https://nasa.gov:bad/x']
        self.assertEqual(recon.scoped_urls(values, 'nasa.gov', 5),
                         ['https://nasa.gov/a.pdf', 'https://ntrs.nasa.gov/b.pdf'])

    def test_dry_run_has_no_worker_no_sleep_and_valid_json(self):
        with patch('recon.subprocess.run') as worker, patch('recon.time.sleep') as sleep:
            result = recon.run_recon('example.com', dry_run=True)
        worker.assert_not_called()
        sleep.assert_not_called()
        self.assertEqual(result['status'], 'dry_run')
        self.assertEqual(len(result['results']), 3)
        self.assertEqual(json.loads(Path(result['output_file']).read_text(encoding='utf-8')), result)

    def test_reject_output_outside_demo(self):
        with self.assertRaises(ValueError):
            recon.run_recon('example.com', dry_run=True, output_dir=BASE.parent)

    def test_empty_and_network_error_are_distinct(self):
        def run_with(status):
            def worker(command, **kwargs):
                work = Path(command[-1]).parent
                (work / 'response.json').write_text(json.dumps({'status': status, 'urls': [],
                        'error': None if status == 'empty' else 'offline fixture error'}), encoding='utf-8')
                return Mock(returncode=0)
            with patch('recon.subprocess.run', side_effect=worker):
                return recon.run_recon('example.com', mode='search')
        self.assertEqual(run_with('empty')['status'], 'empty')
        failed = run_with('network_error')
        self.assertEqual(failed['status'], 'error')
        self.assertEqual(failed['results'][0]['status'], 'network_error')

    def test_block_stops_remaining_dorks(self):
        def worker(command, **kwargs):
            (Path(command[-1]).parent / 'response.json').write_text(json.dumps(
                {'status': 'blocked', 'error': 'fixture CAPTCHA', 'urls': []}), encoding='utf-8')
            return Mock(returncode=0)
        with patch('recon.subprocess.run', side_effect=worker) as call, patch('recon.time.sleep') as sleep:
            result = recon.run_recon('example.com')
        self.assertEqual(call.call_count, 1)
        sleep.assert_not_called()
        self.assertEqual([r['status'] for r in result['results']], ['blocked', 'skipped', 'skipped'])

    def test_sequential_delay_and_provenance(self):
        def worker(command, **kwargs):
            work = Path(command[-1]).parent
            (work / 'response.json').write_text(json.dumps({'status': 'success', 'error': None,
                'urls': ['https://example.com/shared.pdf']}), encoding='utf-8')
            return Mock(returncode=0)
        with patch('recon.subprocess.run', side_effect=worker), patch('recon.time.sleep') as sleep:
            result = recon.run_recon('example.com')
        self.assertEqual(sleep.call_count, 2)
        self.assertTrue(all(10 <= call.args[0] <= 15 for call in sleep.call_args_list))
        self.assertEqual(len(result['unique_urls']), 1)
        self.assertEqual(len(result['unique_urls'][0]['queries']), 3)


@unittest.skipUnless(importlib.util.find_spec('requests') and importlib.util.find_spec('bs4'),
                     'Cần cài requirements.txt để kiểm tra transport')
class TransportTests(unittest.TestCase):
    def setUp(self):
        self.transport = GoogleTransport()

    def response(self, html='', status=200, headers=None):
        return Mock(status_code=status, text=html, headers=headers or {})

    def test_target_url_is_never_requested(self):
        with patch.object(self.transport.session, 'get') as get:
            with self.assertRaises(StopSearch):
                self.transport.get_page('https://nasa.gov/report.pdf')
        get.assert_not_called()

    def test_http_429_and_captcha_stop_without_retry(self):
        for response in [self.response(status=429), self.response('<form action="/sorry/index"><div id="captcha"></div></form>')]:
            transport = GoogleTransport()
            with patch.object(transport.session, 'get', return_value=response) as get:
                with self.assertRaises(StopSearch) as caught:
                    transport.get_page('https://www.google.com/search?q=test')
            self.assertEqual(caught.exception.status, 'blocked')
            self.assertEqual(get.call_count, 1)
            self.assertFalse(get.call_args.kwargs['allow_redirects'])

    def test_unknown_html_is_not_empty(self):
        with patch.object(self.transport.session, 'get', return_value=self.response('<html>Unknown layout</html>')):
            with self.assertRaises(StopSearch) as caught:
                self.transport.get_page('https://www.google.com/search?q=test')
        self.assertEqual(caught.exception.status, 'parse_error')

    def test_explicit_empty_is_recognized(self):
        with patch.object(self.transport.session, 'get', return_value=self.response('<p>Your search did not match any documents.</p>')):
            self.transport.get_page('https://www.google.com/search?q=test')
        self.assertTrue(self.transport.explicit_empty)

    def test_consent_redirect_not_followed(self):
        with patch.object(self.transport.session, 'get', return_value=self.response(status=302,
                          headers={'Location': 'https://consent.google.com/'})) as get:
            with self.assertRaises(StopSearch) as caught:
                self.transport.get_page('https://www.google.com/')
        self.assertEqual(caught.exception.status, 'blocked')
        self.assertEqual(get.call_count, 1)


@unittest.skipUnless(importlib.util.find_spec('googlesearch') and importlib.util.find_spec('yagooglesearch'),
                     'Cần cài requirements.txt để kiểm tra backend thật với HTML giả lập')
class BackendFixtureTests(unittest.TestCase):
    def test_real_backends_do_not_swallow_block(self):
        class BlockedTransport:
            USER_AGENT = 'Offline-test'
            count = 1
            def get_page(self, *_args, **_kwargs):
                raise StopSearch('blocked', 'offline fixture CAPTCHA')
        for mode in ['search', 'dorks']:
            work = BASE / 'output' / ('blocked_fixture_' + uuid4().hex[:8])
            work.mkdir(parents=True)
            with chdir(work), patch('_worker.GoogleTransport', BlockedTransport):
                result = execute({'mode': mode, 'domain': 'example.com', 'expression': 'filetype:pdf',
                                  'query': 'site:example.com filetype:pdf', 'limit': 3}, work)
            self.assertEqual(result['status'], 'blocked', result)

    def test_real_backends_recognize_explicit_empty(self):
        class EmptyTransport:
            USER_AGENT = 'Offline-test'
            count = 2
            explicit_empty = True
            def get_page(self, *_args, **_kwargs):
                return '<div id="search">Your search did not match any documents.</div>'
        for mode in ['search', 'dorks']:
            work = BASE / 'output' / ('empty_fixture_' + uuid4().hex[:8])
            work.mkdir(parents=True)
            with chdir(work), patch('_worker.GoogleTransport', EmptyTransport):
                result = execute({'mode': mode, 'domain': 'example.com', 'expression': 'filetype:pdf',
                                  'query': 'site:example.com filetype:pdf', 'limit': 3}, work)
            self.assertEqual(result['status'], 'empty', result)

    def test_real_libraries_parse_fixture_html(self):
        # The real libraries parse the fixture; no requests leave the process.
        class FixtureTransport:
            USER_AGENT = 'Offline-test'
            count = 0
            explicit_empty = False
            def get_page(self, url, *_args, **_kwargs):
                self.count += 1
                return '<div id="search">' + ''.join(
                    f'<a href="https://example.com/{i}.pdf"><h3>Fixture {i}</h3></a>'
                    for i in range(3)) + '</div>'
        for mode in ['search', 'dorks']:
            work = BASE / 'output' / ('fixture_' + uuid4().hex[:8])
            work.mkdir(parents=True)
            with chdir(work), patch('_worker.GoogleTransport', FixtureTransport):
                result = execute({'mode': mode, 'domain': 'example.com', 'expression': 'filetype:pdf',
                                  'query': 'site:example.com filetype:pdf', 'limit': 3}, work)
            self.assertEqual(result['status'], 'success', result)
            self.assertEqual(len(result['urls']), 3)


if __name__ == '__main__':
    unittest.main()
