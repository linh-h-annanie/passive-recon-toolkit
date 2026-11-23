"""Certificate Transparency lookup through crt.sh."""
import ipaddress
import re
import time
from datetime import datetime, timezone

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MAX_CERTS = 50


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


def parse_datetime(value):
    if not value:
        return None
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)


def request_certificates(domain, timeout=20):
    import requests
    last_error = None
    for attempt in range(2):
        try:
            response = requests.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=timeout, headers={"User-Agent": "PassiveReconToolkit/1.0"})
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, list):
                raise ValueError("unexpected crt.sh response")
            return data
        except Exception as exc:
            last_error = exc
            if attempt == 0:
                time.sleep(2)
    raise last_error


def normalize_certs(raw_certificates, domain, now=None):
    now = now or datetime.now(timezone.utc)
    certificates, subdomains, seen = [], set(), set()
    for raw in raw_certificates:
        cert_id = raw.get("id")
        cert_key = (
            ("id", cert_id)
            if cert_id is not None
            else ("fallback", raw.get("name_value"), raw.get("not_after"))
        )
        if cert_key in seen:
            continue
        seen.add(cert_key)
        names = set()
        for raw_name in str(raw.get("name_value", "")).splitlines():
            name = raw_name.strip().lower().removeprefix("*.")
            if name and (name == domain or name.endswith("." + domain)):
                names.add(name)
                subdomains.add(name)
        not_before = parse_datetime(raw.get("not_before"))
        not_after = parse_datetime(raw.get("not_after"))
        expired = bool(not_after and not_after < now)
        days_left = (not_after - now).days if not_after else None
        certificates.append({"id": raw.get("id"), "names": sorted(names), "not_before": not_before.isoformat() if not_before else None, "not_after": not_after.isoformat() if not_after else None, "issuer": raw.get("issuer_name"), "expired": expired, "days_left": days_left})
    certificates.sort(key=lambda x: x["not_after"] or "", reverse=True)
    expiring = [x for x in certificates if not x["expired"] and x["days_left"] is not None and 0 <= x["days_left"] <= 30]
    return {"subdomains": sorted(subdomains), "certificates": certificates[:MAX_CERTS], "total_certificates": len(certificates), "valid_certificates": sum(not x["expired"] for x in certificates), "expired_certificates": sum(x["expired"] for x in certificates), "expiring_within_30_days": expiring, "notes": []}


def result(status, data=None, error=None):
    return {"module": "crtsh", "status": status, "source": "crt.sh", "data": data or {}, "error": error, "timestamp": now_iso()}


def run(target, config=None):
    if is_ip(target):
        return result("skipped", error="crt.sh requires a domain name")
    domain = clean_domain(target)
    if not domain:
        return result("error", error=f"Invalid domain: {target!r}")
    try:
        return result("ok", normalize_certs(request_certificates(domain), domain))
    except Exception as exc:
        return result("error", error=f"{type(exc).__name__}: {exc}")
