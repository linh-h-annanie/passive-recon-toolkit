"""Google Search transport; một request, không retry, không mở URL đích.
Adapter cho giao diện SearchClient mà Pagodo 2.8 sử dụng.
Chỉ dùng thư viện chuẩn để tránh xung đột google/googlesearch-python.
"""
import socket
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

LAST_ERROR = None
MAX_BYTES = 2 * 1024 * 1024


class SearchError(Exception):
    """Lỗi mạng, chặn truy vấn hoặc HTML chưa nhận diện được."""

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Không đi theo chuyển hướng sang CAPTCHA/consent hoặc máy chủ khác.
        return None


class ResultParser(HTMLParser):
    """Chỉ lấy liên kết chứa heading h3 của kết quả tìm kiếm."""

    def __init__(self):
        super().__init__()
        self.link = None
        self.urls = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.link = dict(attrs).get("href")
        if tag == "h3" and self.link:
            self.urls.append(self.link)

    def handle_endtag(self, tag):
        if tag == "a":
            self.link = None


def parse_results(html):
    """Phân biệt URL, trang rỗng rõ ràng và phản hồi không nhận diện."""
    lower = html.lower()
    if any(marker in lower for marker in (
        "unusual traffic", "g-recaptcha", "before you continue to google",
        'action="https://consent.google', "/sorry/", "id=\"captcha\"",
    )):
        raise SearchError("blocked: Google yêu cầu CAPTCHA/consent; dừng truy vấn")
    parser = ResultParser()
    parser.feed(html)
    urls = []
    for url in parser.urls:
        try:
            parts = urlsplit(url)
            # Chỉ giải mã redirect của Google, không truy cập URL này.
            if (parts.path == "/url" and (
                    url.startswith("/url?") or parts.hostname in ("www.google.com", "google.com"))):
                values = parse_qs(parts.query)
                url = (values.get("q") or values.get("url") or [""])[0]
            if urlsplit(url).scheme in ("http", "https"):
                urls.append(url)
        except ValueError:
            continue
    if urls:
        return urls
    if "did not match any documents" in lower or "no results found for" in lower:
        return []
    raise SearchError("unrecognized_html: chưa thể phân biệt rỗng với thay đổi HTML")


def search(query, limit=3, timeout=8):
    """Gửi duy nhất một yêu cầu tới Google, TLS mặc định được xác minh."""
    request = Request(
        "https://www.google.com/search?" + urlencode({
            "q": query, "num": limit, "hl": "en", "safe": "active",
        }),
        headers={"User-Agent": "PassiveReconToolkit-Education/1.0"},
    )
    # Không lấy proxy môi trường và không tự theo redirect.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise SearchError("response_too_large: vượt 2 MiB")
            html = body.decode("utf-8", errors="replace")
        return parse_results(html)[:limit]
    except HTTPError as exc:
        try:
            raise SearchError(f"http_{exc.code}: dừng, không tự thử lại") from exc
        finally:
            exc.close()
    except (TimeoutError, socket.timeout) as exc:
        raise SearchError("timeout: Google không phản hồi đúng hạn") from exc
    except URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            raise SearchError("timeout: Google không phản hồi đúng hạn") from exc
        raise SearchError(f"connection_error: {exc.reason}") from exc


class SearchClient:
    """Giao diện tương thích Pagodo, thay transport yagooglesearch."""

    def __init__(self, query, max_search_result_urls_to_return=3, **kwargs):
        self.query = query
        self.limit = min(max_search_result_urls_to_return, 3)
        self.user_agent = "PassiveReconToolkit-Education/1.0"

    def assign_random_user_agent(self):
        """Giữ User-Agent cố định dù Pagodo gọi phương thức này."""

    def search(self):
        global LAST_ERROR
        try:
            return search(self.query, self.limit)
        except Exception as exc:
            # Pagodo bắt Exception bên trong go(); lưu lỗi để caller nhận biết.
            LAST_ERROR = str(exc)
            raise
