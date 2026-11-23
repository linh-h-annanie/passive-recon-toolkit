"""DNS records and reverse lookup."""
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

RECORD_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA")
MAX_REVERSE = 10
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def clean_domain(value):
    text = str(value).strip().lower()
    text = re.sub(r"^[a-z]+://", "", text).split("/")[0].split(":")[0].rstrip(".")
    return text if DOMAIN_RE.match(text) else None


def reverse_lookup(ip, timeout=3):
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        return executor.submit(socket.gethostbyaddr, ip).result(timeout=timeout)[0]
    except Exception:
        return None
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def reverse_many(ips):
    ips = ips[:MAX_REVERSE]
    if not ips:
        return {}
    with ThreadPoolExecutor(max_workers=len(ips)) as pool:
        return dict(zip(ips, pool.map(reverse_lookup, ips)))


def txt_text(answer):
    strings = getattr(answer, "strings", None)
    if strings:
        return "".join(s.decode("utf-8", "replace") if isinstance(s, bytes) else str(s) for s in strings)
    return answer.to_text().strip('"')


def query_type(resolver, domain, record_type):
    import dns.exception
    import dns.resolver
    try:
        answers = resolver.resolve(domain, record_type)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [], None
    except dns.exception.DNSException:
        return [], f"{record_type} query failed"
    return [txt_text(a) if record_type == "TXT" else a.to_text() for a in answers], None


def result(status, data=None, error=None, source="dnspython + socket"):
    return {"module": "dns", "status": status, "source": source, "data": data or {}, "error": error, "timestamp": now_iso()}


def run(target, config=None):
    target = str(target).strip()
    if is_ip(target):
        return result("ok", {"records": {}, "ips": [target], "reverse": reverse_many([target]), "notes": ["Input is an IP; forward lookup skipped"]}, source="socket reverse lookup")
    domain = clean_domain(target)
    if not domain:
        return result("error", error=f"Invalid domain: {target!r}")
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        records, notes = {}, []
        for record_type in RECORD_TYPES:
            values, note = query_type(resolver, domain, record_type)
            records[record_type] = values
            if note:
                notes.append(note)
        ips = list(dict.fromkeys(v for v in records["A"] if is_ip(v)))
        has_data = any(records.values())
        data = {"records": records, "ips": ips, "reverse": reverse_many(ips), "notes": notes}
        return result("ok", data) if has_data else result("error", data, "No DNS records returned")
    except Exception as exc:
        return result("error", error=f"{type(exc).__name__}: {exc}")
