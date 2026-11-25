"""Certificate Transparency lookup through crt.sh."""
import ipaddress
import json
import re
import time
from datetime import datetime, timezone

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MAX_CERTS = 50
MAX_BYTES = 30 * 1024 * 1024
CRTSH_URL = "https://crt.sh/"


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


class ResponseTooLarge(Exception):
    pass


def request_certificates(domain, timeout=(5, 30), attempts=3, max_bytes=MAX_BYTES):
    """Query crt.sh. Retries timeouts, connection errors, 429/5xx and broken JSON with a growing pause; never retries other 4xx."""
    import requests
    last_error = None
    for attempt in range(attempts):
        try:
            with requests.get(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"}, timeout=timeout,
                              headers={"User-Agent": "PassiveReconToolkit/1.0", "Accept": "application/json"},
                              stream=True) as response:
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_content(65536):
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        raise ResponseTooLarge(f"crt.sh response larger than {max_bytes // (1024 * 1024)} MB")
            data = json.loads(bytes(body))
            if not isinstance(data, list):
                raise ValueError("unexpected crt.sh response")
            return data
        except ResponseTooLarge:
            raise
        except requests.HTTPError as exc:
            code = exc.response.status_code if exc.response is not None else 0
            # crt.sh may return 404 temporarily while overloaded. Retry it
            # like 429 and 5xx responses, but fail fast for other 4xx errors.
            retryable = code == 404 or code == 429 or code >= 500
            if not retryable:
                raise
            last_error = exc
        except Exception as exc:  # timeout, connection error, HTML/truncated JSON
            last_error = exc
        if attempt < attempts - 1:
            time.sleep(2 * (attempt + 1))
    raise last_error


def normalize_certs(raw_certificates, domain, now=None):
    now = now or datetime.now(timezone.utc)
    certificates, subdomains, seen = [], set(), set()
    duplicates = out_of_scope = 0
    for raw in raw_certificates:
        names = set()
        for raw_name in str(raw.get("name_value", "")).splitlines():
            name = raw_name.strip().lower().removeprefix("*.")
            if name and (name == domain or name.endswith("." + domain)):
                names.add(name)
        if not names:
            out_of_scope += 1
            continue
        not_before = parse_datetime(raw.get("not_before"))
        not_after = parse_datetime(raw.get("not_after"))
        issuer = raw.get("issuer_name")
        # crt.sh lists a precertificate and its final certificate as two rows with different ids but identical content
        signature = (issuer, not_before, not_after, tuple(sorted(names)))
        if signature in seen:
            duplicates += 1
            continue
        seen.add(signature)
        subdomains.update(n for n in names if n != domain)
        certificates.append({"id": raw.get("id"), "names": sorted(names), "not_before": not_before.isoformat() if not_before else None, "not_after": not_after.isoformat() if not_after else None, "issuer": issuer, "expired": bool(not_after and not_after < now), "days_left": (not_after - now).days if not_after else None})
    certificates.sort(key=lambda x: x["not_after"] or "", reverse=True)
    expiring = [x for x in certificates if not x["expired"] and x["days_left"] is not None and 0 <= x["days_left"] <= 30]
    notes = [f"{out_of_scope} rows ignored: no name inside {domain}"] if out_of_scope else []
    return {"subdomains": sorted(subdomains), "certificates": certificates[:MAX_CERTS], "total_certificates": len(certificates), "valid_certificates": sum(not x["expired"] for x in certificates), "expired_certificates": sum(x["expired"] for x in certificates), "duplicates_removed": duplicates, "expiring_within_30_days": expiring, "notes": notes}


def result(status, data=None, error=None):
    return {"module": "crtsh", "status": status, "source": "crt.sh", "data": data or {}, "error": error, "timestamp": now_iso()}


def run(target, config=None):
    if is_ip(target):
        return result("skipped", error="crt.sh requires a domain name")
    domain = clean_domain(target)
    if not domain:
        return result("error", error=f"Invalid domain: {target!r}")
    try:
        cfg = config if isinstance(config, dict) else {}
        raw = request_certificates(domain, timeout=cfg.get("crtsh_timeout", (5, 30)), attempts=cfg.get("crtsh_attempts", 3))
        return result("ok", normalize_certs(raw, domain))
    except Exception as exc:
        return result("error", error=f"{type(exc).__name__}: {exc} (crt.sh is often overloaded; run again later)")
