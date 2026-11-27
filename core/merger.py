"""Merge and deduplicate passive reconnaissance outputs from Shodan and Censys."""

from datetime import datetime, timezone

RISKY_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}


def merge_shodan_censys(shodan_result, censys_result):
    """
    Combine service records from Shodan and Censys into a single deduplicated list.
    Returns:
        {
            "services": [{"ip": ..., "port": ..., "transport": ..., "service": ..., "source": ...}],
            "hosts": [...],
            "warnings": [...],
        }
    """
    merged_map = {}
    hosts_map = {}
    warnings = []

    for mod_res in (shodan_result, censys_result):
        if not isinstance(mod_res, dict) or mod_res.get("status") != "ok":
            continue
        source_name = mod_res.get("source") or mod_res.get("module", "Unknown").capitalize()
        data = mod_res.get("data") or {}

        for host in data.get("hosts") or []:
            ip = host.get("ip")
            if not ip:
                continue
            existing_host = hosts_map.setdefault(ip, {
                "ip": ip,
                "org": None,
                "asn": None,
                "country": None,
                "city": None,
                "ports": set(),
                "vulns": set(),
                "sources": [],
            })
            for field in ("org", "asn", "country", "city"):
                if not existing_host[field] and host.get(field):
                    existing_host[field] = host[field]
            existing_host["ports"].update(host.get("ports") or [])
            existing_host["vulns"].update(host.get("vulns") or [])
            if source_name not in existing_host["sources"]:
                existing_host["sources"].append(source_name)

        for svc in data.get("services") or []:
            ip = svc.get("ip")
            port = svc.get("port")
            if not ip or port is None:
                continue
            transport = str(svc.get("transport", "tcp")).lower()
            key = (ip, int(port), transport)

            if key not in merged_map:
                merged_map[key] = {
                    "ip": ip,
                    "port": int(port),
                    "transport": transport,
                    "service": svc.get("service") or "unknown",
                    "product": svc.get("product"),
                    "version": svc.get("version"),
                    "banner": svc.get("banner") or "",
                    "sources": [source_name],
                }
            else:
                entry = merged_map[key]
                if source_name not in entry["sources"]:
                    entry["sources"].append(source_name)
                if entry["service"] in ("", "unknown") and svc.get("service"):
                    entry["service"] = svc["service"]
                if not entry["product"] and svc.get("product"):
                    entry["product"] = svc["product"]
                if not entry["version"] and svc.get("version"):
                    entry["version"] = svc["version"]
                if not entry["banner"] and svc.get("banner"):
                    entry["banner"] = svc["banner"]

    merged_services = []
    for key in sorted(merged_map.keys(), key=lambda x: (x[0], x[1])):
        item = merged_map[key]
        label = item["service"]
        if item["product"] and item["product"].lower() not in label.lower():
            label = f"{label} ({item['product']})"
        if item["version"]:
            label = f"{label} {item['version']}"

        merged_services.append({
            "ip": item["ip"],
            "port": item["port"],
            "transport": item["transport"],
            "service": label,
            "banner": item["banner"],
            "source": ", ".join(item["sources"]),
        })

        if item["port"] in RISKY_PORTS:
            warnings.append(
                f"Exposed sensitive service on {item['ip']}:{item['port']}/{item['transport']} "
                f"({RISKY_PORTS[item['port']]}) via {', '.join(item['sources'])}"
            )

    merged_hosts = []
    for ip in sorted(hosts_map.keys()):
        h = hosts_map[ip]
        vulns = sorted(h["vulns"])
        if vulns:
            warnings.append(f"{ip} has {len(vulns)} known CVE(s) in Shodan: {', '.join(vulns[:5])}")
        merged_hosts.append({
            "ip": ip,
            "org": h["org"],
            "asn": h["asn"],
            "country": h["country"],
            "city": h["city"],
            "ports": sorted(h["ports"]),
            "vulns": vulns,
            "source": ", ".join(h["sources"]),
        })

    return {
        "services": merged_services,
        "hosts": merged_hosts,
        "warnings": warnings,
    }


def merge_all(target, results):
    """Gộp kết quả của mọi module (mỗi module trả về dict theo 'hợp đồng' chung)."""
    merged = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"ok": [], "skipped": [], "error": []},
        "modules": {},   # dữ liệu gốc của từng module
        "network": {},   # Shodan + Censys đã gộp, loại trùng
        "warnings": [],
    }

    by_module = {}
    for res in results:
        if not isinstance(res, dict):
            continue
        name = str(res.get("module") or "unknown").lower()
        status = res.get("status")
        by_module[name] = res

        if status == "ok":
            merged["summary"]["ok"].append(name)
            merged["modules"][name] = res.get("data") or {}
        elif status == "skipped":
            merged["summary"]["skipped"].append({"module": name, "reason": res.get("error")})
        else:
            partial = bool(res.get("data"))
            merged["summary"]["error"].append(
                {"module": name, "reason": res.get("error"), "partial_data": partial}
            )
            if partial:  # giữ lại dữ liệu một phần (ví dụ dorks bị Google chặn giữa chừng)
                merged["modules"][name] = res["data"]

    network = merge_shodan_censys(by_module.get("shodan"), by_module.get("censys"))
    merged["network"] = network
    merged["warnings"].extend(network["warnings"])

    days = (merged["modules"].get("whois") or {}).get("days_to_expiry")
    if days is not None and days < 30:
        merged["warnings"].append(f"Domain expires in {days} day(s)")

    expiring = (merged["modules"].get("crtsh") or {}).get("expiring_within_30_days") or []
    if expiring:
        merged["warnings"].append(f"{len(expiring)} certificate(s) expire within 30 days")

    if (merged["modules"].get("dorks") or {}).get("mode") == "demo":
        merged["warnings"].append("Dorks data is DEMO (synthetic), not real search results")

    return merged