import os
from datetime import datetime, timezone

from modules.common import classify_exception, redact
from modules.shodan_mod import load_env_key, resolve_targets

MAX_BANNER_LEN = 200
CENSYS_V3_HOST_URL = "https://api.platform.censys.io/v3/global/asset/host/{ip}"
CENSYS_V2_HOST_URL = "https://search.censys.io/api/v2/hosts/{ip}"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _fetch_censys_v3(token, ip, org_id="", timeout=(5, 15)):
    import requests
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.censys.api.v3.host.v1+json",
        "User-Agent": "PassiveReconToolkit/1.0",
    }
    if org_id:
        headers["X-Organization-ID"] = org_id
    resp = requests.get(CENSYS_V3_HOST_URL.format(ip=ip), headers=headers, timeout=timeout, allow_redirects=False)
    resp.raise_for_status()
    payload = resp.json()
    return (payload.get("result") or {}).get("resource") or payload.get("result") or payload


def _fetch_censys_v2(api_id, api_secret, ip, timeout=(5, 15)):
    import requests
    headers = {
        "Accept": "application/json",
        "User-Agent": "PassiveReconToolkit/1.0",
    }
    resp = requests.get(
        CENSYS_V2_HOST_URL.format(ip=ip),
        auth=(api_id, api_secret),
        headers=headers,
        timeout=timeout,
        allow_redirects=False,
    )
    resp.raise_for_status()
    payload = resp.json()
    return payload.get("result") or payload


def normalize_censys_host(raw, ip):
    services = []
    ports = set()

    for item in raw.get("services") or []:
        port = item.get("port")
        if port is None:
            continue
        ports.add(int(port))
        transport = str(item.get("transport_protocol", "tcp")).lower()
        service_name = (
            item.get("extended_service_name")
            or item.get("service_name")
            or item.get("protocol")
            or "unknown"
        )
        software_list = item.get("software") or []
        product = software_list[0].get("product") if software_list and isinstance(software_list[0], dict) else None
        version = software_list[0].get("version") if software_list and isinstance(software_list[0], dict) else None
        banner = str(item.get("banner", "")).strip().replace("\r\n", " ")[:MAX_BANNER_LEN]

        services.append({
            "ip": ip,
            "port": int(port),
            "transport": transport,
            "service": str(service_name),
            "product": product,
            "version": version,
            "banner": banner,
            "source": "Censys",
        })

    loc = raw.get("location") or {}
    asn_info = raw.get("autonomous_system") or {}
    asn_val = asn_info.get("asn")

    host_info = {
        "ip": ip,
        "org": asn_info.get("name"),
        "isp": asn_info.get("name"),
        "asn": f"AS{asn_val}" if asn_val is not None else None,
        "country": loc.get("country"),
        "city": loc.get("city"),
        "os": (raw.get("operating_system") or {}).get("product"),
        "hostnames": raw.get("dns", {}).get("names") if isinstance(raw.get("dns"), dict) else [],
        "ports": sorted(ports),
        "vulns": [],
    }
    return host_info, services


def result(status, data=None, error=None):
    return {
        "module": "censys",
        "status": status,
        "source": "Censys",
        "data": data or {},
        "error": error,
        "timestamp": now_iso(),
    }


def run(target, config=None):
    token = load_env_key("CENSYS_API_TOKEN", config)
    api_id = load_env_key("CENSYS_API_ID", config)
    api_secret = load_env_key("CENSYS_API_SECRET", config)
    org_id = load_env_key("CENSYS_ORG_ID", config)

    if not token and not (api_id and api_secret):
        return result("skipped", error="Missing CENSYS_API_ID or CENSYS_API_SECRET")

    ips, notes = resolve_targets(target)
    if not ips:
        reason = notes[0] if notes else f"No valid public IP from target: {target!r}"
        status = "skipped" if "Private" in reason else "error"
        return result(status, error=reason)

    cfg = config if isinstance(config, dict) else {}
    timeout = cfg.get("censys_timeout", (5, 15))

    hosts, all_services, errors, reasons = [], [], [], []
    for ip in ips:
        try:
            if token:
                raw = _fetch_censys_v3(token, ip, org_id=org_id, timeout=timeout)
            else:
                raw = _fetch_censys_v2(api_id, api_secret, ip, timeout=timeout)
            host_info, services = normalize_censys_host(raw, ip)
            hosts.append(host_info)
            all_services.extend(services)
        except Exception as exc:
            errors.append(redact(f"{ip}: {type(exc).__name__}: {exc}", token, api_id, api_secret))
            reasons.append(classify_exception(exc))

    if not hosts and errors:
        return result("error", {"reason": reasons[0] if reasons else "error"}, "; ".join(errors))

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
