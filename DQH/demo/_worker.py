"""Private isolated backend. All third-party side effects stay in its run directory."""
from __future__ import annotations

from http.cookiejar import LWPCookieJar
import importlib
import inspect
import json
import logging
from pathlib import Path
import random
import sys
import time
from types import SimpleNamespace
from urllib.parse import urljoin, urlsplit


class StopSearch(BaseException):
    """Bypass Pagodo's broad except Exception, so a failed dork cannot continue."""
    def __init__(self, status: str, message: str):
        self.status = status
        self.message = message
        super().__init__(message)


class GoogleTransport:
    """Bounded Google-only requests, no retries or consent/CAPTCHA workarounds."""
    USER_AGENT = 'Mozilla/5.0 (compatible; DQH-PassiveReconDemo/1.0)'

    def __init__(self):
        import requests
        self.requests = requests
        self.session = requests.Session()
        self.count = 0
        self.pages = 0
        self.explicit_empty = False
        self.last_request = None

    def get_page(self, url: str, *_args, **_kwargs) -> str:
        from bs4 import BeautifulSoup
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or parsed.hostname not in {'google.com', 'www.google.com'}
                or parsed.path not in {'/', '/search'}):
            raise StopSearch('blocked', 'Đã chặn điều hướng khỏi trang tìm kiếm Google.')
        if self.count >= 4:
            raise StopSearch('request_limit', 'Đạt giới hạn 4 HTTP requests cho một truy vấn.')
        if self.last_request is not None:
            time.sleep(max(0, random.uniform(10, 15) - (time.monotonic() - self.last_request)))
        self.last_request = time.monotonic()
        self.count += 1
        try:
            response = self.session.get(url, headers={'User-Agent': self.USER_AGENT},
                                        timeout=20, allow_redirects=False)
        except self.requests.RequestException as exc:
            raise StopSearch('network_error', str(exc)) from exc
        try:
            if response.status_code in {403, 429}:
                raise StopSearch('blocked', f'Google trả HTTP {response.status_code}; đã dừng, không thử lại.')
            if 300 <= response.status_code < 400:
                target = urlsplit(urljoin(url, response.headers.get('Location', '')))
                # No automatic following, including consent and /sorry redirects.
                status = 'blocked' if target.hostname and ('consent' in target.hostname or target.path.startswith('/sorry')) else 'redirect'
                raise StopSearch(status, 'Google trả chuyển hướng; không tự theo hoặc vượt qua.')
            if response.status_code != 200:
                raise StopSearch('http_error', f'HTTP {response.status_code}')
            html = response.text
        finally:
            response.close()
        lower = html.lower()
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text(' ', strip=True).lower()
        if (soup.select_one('.g-recaptcha, #captcha, form[action*="/sorry/"]')
                or any(s in text for s in ['unusual traffic from your computer network',
                                           'our systems have detected unusual traffic',
                                           'before you continue to google',
                                           'not a robot', 'enable javascript to use search'])
                or '/httpservice/retry/enablejs' in lower):
            raise StopSearch('blocked', 'Google yêu cầu CAPTCHA, consent hoặc JavaScript; đã dừng.')
        if parsed.path == '/search':
            self.pages += 1
            self.explicit_empty = any(s in text for s in ['did not match any documents',
                                                         'no results found for', 'no results containing all your search terms'])
            if not self.explicit_empty and not soup.select_one('#search, #rso, a h3'):
                raise StopSearch('parse_error', 'Không nhận diện được trang kết quả; không coi là kết quả rỗng.')
        return html


def execute(request: dict, work: Path) -> dict:
    transport = None
    try:
        transport = GoogleTransport()
        if request['mode'] == 'search':
            google = importlib.import_module('googlesearch')
            # google==3.0.0 uses stop=, unlike similarly named packages.
            if 'stop' not in inspect.signature(google.search).parameters:
                raise StopSearch('dependency_error', 'Sai gói googlesearch: cần distribution google==3.0.0.')
            google.cookie_jar = LWPCookieJar(str(work / '.google-cookie'))
            google.get_page = transport.get_page
            urls = list(google.search(request['query'], stop=request['limit'], num=10,
                                      pause=0, user_agent=transport.USER_AGENT, verify_ssl=True))
        else:
            yagooglesearch = importlib.import_module('yagooglesearch')
            pagodo = importlib.import_module('vendor.pagodo.pagodo')

            class GuardedClient(yagooglesearch.SearchClient):
                def __init__(self, *args, **kwargs):
                    kwargs.update(yagooglesearch_manages_http_429s=False,
                                  minimum_delay_between_paged_results_in_seconds=10,
                                  user_agent=transport.USER_AGENT)
                    super().__init__(*args, **kwargs)

                def assign_random_user_agent(self):
                    self.user_agent = transport.USER_AGENT
                    return self.user_agent

                def get_page(self, url):
                    return transport.get_page(url)

                def search(self):
                    try:
                        return super().search()
                    except Exception as exc:
                        raise StopSearch('backend_error', str(exc)) from exc

            # Only this isolated module sees the guarded client. Upstream source is unchanged.
            pagodo.yagooglesearch = SimpleNamespace(SearchClient=GuardedClient)
            dorks = work / 'dork.txt'
            dorks.write_text(request['expression'] + '\n', encoding='utf-8')
            pg = pagodo.Pagodo(
                google_dorks_file=str(dorks), domain=request['domain'],
                max_search_result_urls_to_return_per_dork=request['limit'],
                minimum_delay_between_dork_searches_in_seconds=10,
                maximum_delay_between_dork_searches_in_seconds=15,
                save_pagodo_results_to_json_file=str(work / 'pagodo.json'),
                save_urls_to_file=str(work / 'pagodo_urls.txt'),
                specific_log_file_name=str(work / 'pagodo.log'), verbosity=3)
            result = pg.go()
            urls = result['dorks'][request['expression']]['urls']
        if not urls and not transport.explicit_empty:
            raise StopSearch('parse_error', 'Không trích được URL và không có thông báo hết kết quả rõ ràng.')
        return {'status': 'success' if urls else 'empty', 'urls': urls,
                'error': None, 'request_count': transport.count}
    except StopSearch as exc:
        return {'status': exc.status, 'urls': [], 'error': exc.message,
                'request_count': transport.count if transport else 0}
    except ImportError as exc:
        return {'status': 'dependency_error', 'urls': [], 'error': str(exc)}
    except Exception as exc:
        return {'status': 'backend_error', 'urls': [], 'error': f'{type(exc).__name__}: {exc}'}


def main():
    work = Path(sys.argv[1]).resolve().parent
    # Called only by recon.py with a cwd underneath its output directory.
    base = Path(__file__).resolve().parent
    if not work.is_relative_to(base) or Path.cwd().resolve() != work:
        raise ValueError('Worker phải chạy trong thư mục đầu ra bên trong DQH/demo.')
    request = json.loads((work / 'request.json').read_text(encoding='utf-8'))
    response = execute(request, work)
    (work / 'response.json').write_text(json.dumps(response, ensure_ascii=False, indent=2), encoding='utf-8')
    logging.shutdown()


if __name__ == '__main__':
    main()
