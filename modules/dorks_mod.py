

import argparse
import importlib.util
import ipaddress
import json
import logging
import random
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "Google Search / Pagodo"
# Hai dork và một tìm kiếm thông thường; đều nhắm nội dung công khai.
QUERIES = ('filetype:pdf "guide"', 'intitle:"documentation"', '"public documentation"')


def result(status, data=None, error=None):
    """Tạo định dạng chung; timestamp tương tự module hiện có của nhóm."""
    return {"module": "dorks", "status": status, "source": SOURCE,
            "data": data or {}, "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat()}


def clean_domain(target):
    """Chuẩn hóa domain/URL HTTP(S), IDNA; từ chối IP và query injection."""
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Domain không được rỗng")
    if any(ord(char) < 32 or ord(char) == 127 for char in target):
        raise ValueError("Domain không được chứa ký tự điều khiển")
    text = target.strip()
    try:
        ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        pass
    else:
        return None
    parsed = urlsplit(text if "://" in text else "//" + text)
    if parsed.scheme not in ("", "http", "https") or parsed.username or parsed.password:
        raise ValueError("Chỉ nhận domain hoặc URL HTTP(S) không chứa đăng nhập")
    if parsed.port is not None:
        raise ValueError("Không nhận cổng trong domain")
    host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return None
    labels = host.split(".")
    if (len(host) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
                   for p in labels)):
        raise ValueError("Domain không hợp lệ")
    return host


def normalize_urls(urls, domain):
    """Lọc HTTP(S) đúng domain/subdomain, bỏ fragment và URL trùng."""
    cleaned = []
    for url in urls:
        if not isinstance(url, str) or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
            continue
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").encode("idna").decode("ascii").lower()
            if (parts.scheme not in ("http", "https") or parts.username or parts.password
                    or parts.port not in (None, 80, 443)
                    or not (host == domain or host.endswith("." + domain))):
                continue
            port = f":{parts.port}" if parts.port and parts.port != (
                443 if parts.scheme == "https" else 80) else ""
            canonical = urlunsplit((parts.scheme, host + port, parts.path or "/", parts.query, ""))
            if canonical not in cleaned:
                cleaned.append(canonical)
        except (ValueError, UnicodeError):
            continue
    return cleaned[:3]


def collect(domain, backend="pagodo", mode="live"):
    """Thu thập từng truy vấn, dừng ngay khi lỗi; giữ kết quả từng phần."""
    from modules import google_search_client as client
    data = {"target": domain, "backend": backend, "mode": mode,
            "queries": [], "urls": [], "notes": []}
    for index, suffix in enumerate(QUERIES):
        query = f"site:{domain} {suffix}"
        try:
            if mode == "demo":
                # URL minh họa tự tạo, tuyệt đối không tuyên bố là kết quả Google.
                raw = [f"https://{domain}/demo-public-guide.pdf"] if index == 0 else []
            elif backend == "google" or index == 2:
                raw = client.search(query, limit=3)
            else:
                raw = pagodo_search(domain, suffix)
            urls = normalize_urls(raw, domain)
            data["queries"].append({"query": query, "status": "ok", "urls": urls})
            for url in urls:
                if url not in data["urls"]:
                    data["urls"].append(url)
        except Exception as exc:
            data["queries"].append({"query": query, "status": "error", "urls": [], "error": str(exc)})
            data["notes"].append("Đã dừng toàn bộ truy vấn sau lỗi; dữ liệu có thể chưa đầy đủ")
            return result("error", data, str(exc))
        if mode == "live" and index < len(QUERIES) - 1:
            time.sleep(random.uniform(10, 15))
    if mode == "demo":
        data["notes"].append("DỮ LIỆU DEMO TỰ TẠO; không gọi Google, không phải bằng chứng online")
    return result("ok", data)


def pagodo_search(domain, suffix):
    """Chạy Pagodo thật cho một dork, transport Google giới hạn của dự án."""
    from modules import google_search_client as client
    path = ROOT / "vendor" / "pagodo" / "pagodo.py"
    spec = importlib.util.spec_from_file_location("huy_pagodo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    client.LAST_ERROR = None
    logger = logging.getLogger("pagodo")
    previous_handlers = list(logger.handlers)
    previous_level = logger.level
    with tempfile.TemporaryDirectory(prefix="huy_pagodo_") as folder:
        try:
            dorks_file = Path(folder) / "dorks.txt"
            dorks_file.write_text(suffix + "\n", encoding="utf-8")
            pg = module.Pagodo(
                google_dorks_file=str(dorks_file), domain=domain,
                max_search_result_urls_to_return_per_dork=3,
                save_pagodo_results_to_json_file=False, save_urls_to_file=False,
                minimum_delay_between_dork_searches_in_seconds=10,
                maximum_delay_between_dork_searches_in_seconds=15,
                specific_log_file_name=str(Path(folder) / "pagodo.log"), verbosity=1,
            )
            raw = pg.go()
            if client.LAST_ERROR:
                raise client.SearchError(client.LAST_ERROR)
            return raw["dorks"][suffix]["urls"]
        except SystemExit as exc:
            # Vendor có sys.exit(); không để thoát chương trình tích hợp.
            raise client.SearchError(f"pagodo_exit: code={exc.code}") from exc
        finally:
            # Windows cần đóng FileHandler trước khi xóa thư mục tạm.
            for handler in list(logger.handlers):
                if handler not in previous_handlers:
                    handler.close()
                    logger.removeHandler(handler)
            logger.setLevel(previous_level)


def execute_live(domain, backend):
    """Tiến trình con có hạn 65 giây, chặn cả trường hợp socket bị treo."""
    with tempfile.TemporaryDirectory(prefix="huy_worker_") as folder:
        output = Path(folder) / "result.json"
        try:
            completed = subprocess.run(
                [sys.executable, "-m", "modules.dorks_mod", "--worker", "--target",
                 domain, "--backend", backend, "--output", str(output)],
                cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=65,
            )
            if completed.returncode or not output.exists():
                return result("error", error="worker_error: tiến trình tìm kiếm thất bại")
            return json.loads(output.read_text(encoding="utf-8"))
        except subprocess.TimeoutExpired:
            return result("error", error="timeout: đã dừng worker sau 65 giây")


def run(target, config=None):
    """Giao diện tích hợp. Mặc định skipped; bật live rõ ràng hoặc dùng demo."""
    try:
        domain = clean_domain(target)
        if domain is None:
            return result("skipped", error="Google Dorks yêu cầu domain, không nhận IP")
        cfg = config if isinstance(config, dict) else {}
        mode = cfg.get("dorks_mode", "disabled")
        backend = cfg.get("dorks_backend", "pagodo")
        if backend not in ("pagodo", "google"):
            raise ValueError("Backend phải là pagodo hoặc google")
        if mode == "disabled":
            return result("skipped", error="Chưa bật tìm kiếm; chọn dorks_mode=live hoặc demo")
        if mode == "demo":
            return collect(domain, backend, mode="demo")
        if mode != "live":
            raise ValueError("dorks_mode phải là disabled, demo hoặc live")
        return execute_live(domain, backend)
    except Exception as exc:
        return result("error", error=f"{type(exc).__name__}: {exc}")


def cli():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Module của Huy: Google Dorks/Search")
    parser.add_argument("--target", required=True)
    parser.add_argument("--mode", choices=("disabled", "demo", "live"), default="disabled")
    parser.add_argument("--backend", choices=("pagodo", "google"), default="pagodo")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--replay", type=Path, help="Đọc kết quả JSON đã lưu, không gọi mạng")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        try:
            domain = clean_domain(args.target)
            outcome = (collect(domain, args.backend) if domain
                       else result("skipped", error="Worker yêu cầu domain, không nhận IP"))
        except Exception as exc:
            outcome = result("error", error=f"worker_error: {exc}")
    elif args.replay:
        try:
            outcome = json.loads(args.replay.read_text(encoding="utf-8"))
            if (outcome.get("module") != "dorks" or outcome.get("status") not in ("ok", "error", "skipped")
                    or outcome.get("data", {}).get("target") != clean_domain(args.target)):
                raise ValueError("JSON không khớp module hoặc target")
            outcome["data"]["replayed"] = True
        except Exception as exc:
            outcome = result("error", error=f"replay_error: {exc}")
    else:
        outcome = run(args.target, {"dorks_mode": args.mode, "dorks_backend": args.backend})
    text = json.dumps(outcome, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    if not args.worker:
        print(text)


if __name__ == "__main__":
    cli()
