"""Passive host and service lookup through Shodan."""
import ipaddress
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

MAX_IPS = 5
MAX_BANNER_LEN = 200
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_env_key(key_name, config=None):
    if isinstance(config, dict):
        val = config.get(key_name) or config.get(key_name.lower())
        if val:
            return str(val).strip()
    val = os.getenv(key_name)
    if val:
        return val.strip()
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip() == key_name:
                return v.strip().strip('"').strip("'")
    return ""


def is_ip(value):
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def is_public_ip(value):
    try:
        return ipaddress.ip_address(str(value).strip()).is_global
    except ValueError:
        return False


def clean_domain(value):
    text = str(value).strip().lower()
    text = re.sub(r"^[a-z]+://", "", text).split("/")[0].split(":")[0].rstrip(".")
    return text if DOMAIN_RE.match(text) else None


def resolve_targets(target):
    """Accept a single IP, list/tuple of IPs, or a domain name and return public IPs."""
    if isinstance(target, (list, tuple, set)):
        ips = [str(x).strip() for x in target if is_public_ip(x)]
        return list(dict.fromkeys(ips))[:MAX_IPS], []

    text = str(target).strip()
    if is_ip(text):
        if not is_public_ip(text):
            return [], ["Private, loopback or reserved IP skipped"]
        return [text], []

    domain = clean_domain(text)
    if not domain:
        return [], [f"Invalid target: {target!r}"]

    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        public_ips = list(dict.fromkeys(ip for ip in ip_list if is_public_ip(ip)))[:MAX_IPS]
        if not public_ips:
            return [], [f"No public IP resolved for {domain}"]
        return public_ips, [f"Resolved {domain} -> {', '.join(public_ips)}"]
    except Exception as exc:
        return [], [f"DNS resolution failed for {domain}: {exc}"]


def _fetch_shodan_host(api_key, ip, timeout=10):
    import shodan
    api = shodan.Shodan(api_key)
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        return executor.submit(api.host, ip).result(timeout=timeout)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def normalize_shodan_host(raw, ip):
    services = []
    for item in raw.get("data", []):
        port = item.get("port")
        if port is None:
            continue
        transport = str(item.get("transport", "tcp")).lower()
        product = item.get("product")
        version = item.get("version")
        module_name = (item.get("_shodan") or {}).get("module", "")
        service_name = product or module_name or "unknown"
        banner = str(item.get("data", "")).strip().replace("\r\n", " ")[:MAX_BANNER_LEN]
        services.append({
            "ip": ip,
            "port": int(port),
            "transport": transport,
            "service": str(service_name),
            "product": product,
            "version": version,
            "banner": banner,
            "source": "Shodan",
        })

    vulns = raw.get("vulns")
    vuln_list = sorted(vulns.keys()) if isinstance(vulns, dict) else sorted(vulns or [])

    host_info = {
        "ip": ip,
        "org": raw.get("org"),
        "isp": raw.get("isp"),
        "asn": raw.get("asn"),
        "country": raw.get("country_name"),
        "city": raw.get("city"),
        "os": raw.get("os"),
        "hostnames": raw.get("hostnames") or [],
        "ports": sorted(set(raw.get("ports") or [])),
        "vulns": vuln_list,
    }
    return host_info, services


def result(status, data=None, error=None):
    return {
        "module": "shodan",
        "status": status,
        "source": "Shodan",
        "data": data or {},
        "error": error,
        "timestamp": now_iso(),
    }


def run(target, config=None):
    api_key = load_env_key("SHODAN_API_KEY", config)
    if not api_key:
        return result("skipped", error="Missing SHODAN_API_KEY")

    ips, notes = resolve_targets(target)
    if not ips:
        reason = notes[0] if notes else f"No valid public IP from target: {target!r}"
        status = "skipped" if "Private" in reason else "error"
        return result(status, error=reason)

    cfg = config if isinstance(config, dict) else {}
    timeout = cfg.get("shodan_timeout", 10)

    hosts, all_services, errors = [], [], []
    for ip in ips:
        try:
            raw = _fetch_shodan_host(api_key, ip, timeout=timeout)
            host_info, services = normalize_shodan_host(raw, ip)
            hosts.append(host_info)
            all_services.extend(services)
        except Exception as exc:
            err_msg = str(exc)
            if "No information available for that IP" in err_msg:
                notes.append(f"{ip}: No Shodan record found")
            else:
                errors.append(f"{ip}: {type(exc).__name__}: {err_msg}")

    if not hosts and errors:
        return result("error", error="; ".join(errors))

    data = {
        "ips_queried": ips,
        "hosts": hosts,
        "services": all_services,
        "total_services": len(all_services),
        "notes": notes + errors,
    }
    return result("ok", data)


if __name__ == "__main__":
    import json
    import sys
    sample_target = sys.argv[1] if len(sys.argv) > 1 else "104.20.23.154"
    print(json.dumps(run(sample_target), indent=2, ensure_ascii=False))
