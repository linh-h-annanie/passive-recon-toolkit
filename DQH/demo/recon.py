"""Domain-scoped Google reconnaissance. Import run_recon from this file."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import random
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

BASE = Path(__file__).resolve().parent


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_domain(value: str) -> str:
    domain = value.strip().rstrip('.').encode('idna').decode('ascii').lower()
    if len(domain) > 253 or '.' not in domain:
        raise ValueError('Domain phải là tên miền đầy đủ, không phải URL hoặc IP.')
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', s)
           for s in domain.split('.')):
        raise ValueError('Domain không được chứa scheme, đường dẫn, cổng hoặc toán tử.')
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError('Hãy dùng domain thay cho địa chỉ IP.')


def build_query(domain: str, expression: str) -> str:
    domain = normalize_domain(domain)
    expression = expression.strip()
    # Disallow operators that can split the scope into a separate OR branch.
    if (not expression or len(expression) > 300 or len(expression.split()) > 24
            or re.search(r'\bsite\s*:|\bOR\b|[|()\r\n\x00-\x1f]', expression, re.I)):
        raise ValueError('Query rỗng/quá dài hoặc chứa site:, OR, |, ngoặc hay ký tự điều khiển.')
    return f'site:{domain} {expression}'


def scoped_urls(values: list[str], domain: str, limit: int) -> list[str]:
    """Keep exact domain/subdomains only; remove fragments and duplicates."""
    urls = []
    for value in values:
        try:
            p = urlsplit(value)
            host = (p.hostname or '').encode('idna').decode('ascii').lower().rstrip('.')
            if (p.scheme not in {'http', 'https'} or p.username or p.password
                    or not (host == domain or host.endswith('.' + domain))):
                continue
            port = p.port  # Validate ports, including malformed input.
            netloc = host if port in (None, 80 if p.scheme == 'http' else 443) else f'{host}:{port}'
            url = urlunsplit((p.scheme.lower(), netloc, p.path or '/', p.query, ''))
        except (ValueError, UnicodeError):
            continue
        if url not in urls:
            urls.append(url)
        if len(urls) == limit:
            break
    return urls


def _inside_demo(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(BASE):
        raise ValueError('Đường dẫn ghi phải nằm trong DQH/demo.')
    return resolved


def run_recon(domain: str, mode: str = 'dorks', query: str = 'filetype:pdf',
              dorks_file: str | Path | None = None, limit: int | None = None,
              dry_run: bool = False, output_dir: str | Path | None = None) -> dict:
    """Run sequentially and save JSON; errors appear in per-query status/error.

    mode: dorks (Pagodo) or search (google==3.0.0). This synchronous function
    uses isolated child processes so third-party logging/patches cannot leak
    into the caller. A caller should invoke live runs sequentially.
    """
    domain = normalize_domain(domain)
    if mode not in {'dorks', 'search'}:
        raise ValueError('mode phải là dorks hoặc search.')
    limit = (3 if mode == 'dorks' else 5) if limit is None else limit
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10:
        raise ValueError('limit phải là số nguyên từ 1 đến 10.')
    if mode == 'dorks':
        path = Path(dorks_file) if dorks_file else BASE / 'dorks.txt'
        if not path.is_absolute():
            path = BASE / path
        expressions = list(dict.fromkeys(s.strip() for s in path.read_text(encoding='utf-8-sig').splitlines()
                                         if s.strip() and not s.lstrip().startswith('#')))
        if not 2 <= len(expressions) <= 3:
            raise ValueError('File dorks phải có 2–3 truy vấn khác nhau.')
    else:
        expressions = [query]
    queries = [build_query(domain, s) for s in expressions]
    output = _inside_demo(Path(output_dir) if output_dir else BASE / 'output')
    run_dir = _inside_demo(output / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '_' + uuid4().hex[:8]))
    run_dir.mkdir(parents=True)
    source = 'pagodo' if mode == 'dorks' else 'google'
    report = {'schema_version': 1, 'source': source, 'domain': domain,
              'dry_run': dry_run, 'started_at': now(), 'completed_at': None,
              'status': '', 'results': [], 'unique_urls': [], 'output_file': str(run_dir / 'results.json')}
    stop = False
    for i, (expression, scoped_query) in enumerate(zip(expressions, queries)):
        row = {'source': source, 'domain': domain, 'query': scoped_query,
               'urls': [], 'started_at': now(), 'completed_at': None, 'status': '', 'error': None}
        if stop:
            row.update(status='skipped', error='Đã dừng sau lỗi của truy vấn trước.')
        elif dry_run:
            row['status'] = 'dry_run'
        else:
            if i:
                delay = random.uniform(10, 15)
                row['delay_before_seconds'] = round(delay, 3)
                time.sleep(delay)
            work = _inside_demo(run_dir / f'query_{i + 1}')
            work.mkdir()
            request = {'mode': mode, 'domain': domain, 'expression': expression,
                       'query': scoped_query, 'limit': limit}
            (work / 'request.json').write_text(json.dumps(request), encoding='utf-8')
            try:
                # -B prevents imports from writing bytecode beside external modules.
                with (work / 'worker.log').open('w', encoding='utf-8') as log:
                    result = subprocess.run([sys.executable, '-B', str(BASE / '_worker.py'),
                                             str(work / 'request.json')], cwd=work,
                                            stdout=log, stderr=log, timeout=180, check=False)
                if result.returncode != 0 or not (work / 'response.json').exists():
                    row.update(status='backend_error', error=f'Worker exit {result.returncode}; xem {work / "worker.log"}')
                else:
                    response = json.loads((work / 'response.json').read_text(encoding='utf-8'))
                    row.update(status=response['status'], error=response.get('error'),
                               urls=scoped_urls(response.get('urls', []), domain, limit))
                    row['request_count'] = response.get('request_count', 0)
                    if row['status'] == 'success' and not row['urls']:
                        row.update(status='scope_filtered', error='Parser trả URL nhưng không có URL hợp lệ thuộc domain.')
            except subprocess.TimeoutExpired:
                row.update(status='timeout', error='Worker vượt thời gian 180 giây, đã dừng.')
            except (OSError, ValueError, KeyError) as exc:
                row.update(status='backend_error', error=str(exc))
            stop = row['status'] not in {'success', 'empty'}
        row['completed_at'] = now()
        report['results'].append(row)
    merged = {}
    for row in report['results']:
        for url in row['urls']:
            merged.setdefault(url, []).append(row['query'])
    report['unique_urls'] = [{'url': u, 'queries': q} for u, q in merged.items()]
    statuses = {r['status'] for r in report['results']}
    report['status'] = ('dry_run' if dry_run else 'error' if statuses - {'success', 'empty'}
                        else 'success' if 'success' in statuses else 'empty')
    report['completed_at'] = now()
    Path(report['output_file']).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description='Google Dorks / Google Search demo - Người 3')
    parser.add_argument('mode', choices=['dorks', 'search'])
    parser.add_argument('--domain', required=True)
    parser.add_argument('--query', default='filetype:pdf')
    parser.add_argument('--dorks-file', type=Path)
    parser.add_argument('--limit', type=int)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    try:
        report = run_recon(**vars(args))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 1 if report['status'] == 'error' else 0


if __name__ == '__main__':
    raise SystemExit(main())
