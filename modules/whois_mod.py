"""WHOIS collection and normalization."""
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def clean_domain(value):
    text = str(value).strip().lower()
    text = re.sub(r"^[a-z]+://", "", text).split("/")[0].split(":")[0].rstrip(".")
    return text if DOMAIN_RE.match(text) else None


def is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def as_list(value):
    return [] if value is None else list(value) if isinstance(value, (list, tuple, set)) else [value]


def parse_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        result = value
    else:
        try:
            result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)


def mask_email(value):
    text = str(value).strip()
    if "@" not in text:
        return "***"
    username, domain = text.split("@", 1)
    return f"{username[:1]}***@{domain}"


def unique_lower(value):
    return sorted({str(x).strip().lower() for x in as_list(value) if x})


def status_codes(value):
    return sorted({str(x).split()[0].lower() for x in as_list(value) if x and str(x).split()})


def normalize_whois(raw, now=None):
    now = now or datetime.now(timezone.utc)
    created = [x for x in (parse_datetime(v) for v in as_list(raw.get("creation_date"))) if x]
    expires = [x for x in (parse_datetime(v) for v in as_list(raw.get("expiration_date"))) if x]
    created = min(created) if created else None
    expires = max(expires) if expires else None
    return {"domain_name": unique_lower(raw.get("domain_name")), "registrar": raw.get("registrar"), "creation_date": created.isoformat() if created else None, "expiration_date": expires.isoformat() if expires else None, "days_to_expiry": (expires - now).days if expires else None, "name_servers": unique_lower(raw.get("name_servers")), "status": status_codes(raw.get("status")), "dnssec": raw.get("dnssec"), "org": raw.get("org"), "country": raw.get("country"), "emails_masked": [mask_email(x) for x in unique_lower(raw.get("emails"))]}


def result(status, data=None, error=None):
    return {"module": "whois", "status": status, "source": "python-whois", "data": data or {}, "error": error, "timestamp": now_iso()}


def run(target, config=None, timeout=15):
    if is_ip(target):
        return result("skipped", error="whois module expects a domain name, got an IP")
    domain = clean_domain(target)
    if not domain:
        return result("error", error=f"Invalid domain: {target!r}")
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        import whois
        raw = executor.submit(whois.whois, domain).result(timeout=timeout)
        raw = dict(raw)
        data = normalize_whois(raw)
        if not (data["registrar"] or data["creation_date"] or data["name_servers"]):
            return result("error", error="No WHOIS data returned (domain may be unregistered or rate-limited)")
        return result("ok", data)
    except Exception as exc:
        return result("error", error=f"{type(exc).__name__}: {exc}")
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
