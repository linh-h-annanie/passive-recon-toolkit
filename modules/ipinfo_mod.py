from modules.common import classify_exception, clean_ip, load_env_key, make_result, redact

SOURCE = "IPinfo"
FIELDS = ("ip", "hostname", "city", "region", "country", "loc", "org", "postal", "timezone")
USEFUL = ("city", "region", "country", "loc", "org")


def result(status, data=None, error=None, reason=None):
    return make_result("ipinfo", SOURCE, status, data, error, reason)


def run(target, config=None):
    cfg = config if isinstance(config, dict) else {}
    token = load_env_key("IPINFO_TOKEN", cfg)
    if not token:
        return result("skipped", error="Missing IPINFO_TOKEN", reason="no_key")

    ip, problem = clean_ip(target)
    if problem == "needs_ip":
        return result("skipped", error="IPinfo module needs an IP address; pass an IP, e.g. from the dns module", reason=problem)
    if problem == "non_public_ip":
        return result("skipped", error="Private, loopback or reserved IP: public targets only", reason=problem)
    if problem:
        return result("error", error="Invalid target: expected a public IP address", reason=problem)

    timeout = cfg.get("ipinfo_timeout", 10)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 60:
        timeout = 10
    try:
        import ipinfo
        handler = ipinfo.getHandler(token, request_options={"timeout": timeout})
        raw = dict(handler.getDetails(ip).all)
    except ImportError:
        return result("error", error="Library 'ipinfo' is not installed (pip install -r requirements.txt)", reason="dependency_missing")
    except Exception as exc:
        return result("error", error=redact(f"{type(exc).__name__}: {exc}", token)[:300], reason=classify_exception(exc))

    data = {name: raw.get(name) for name in FIELDS}
    if not any(data.get(name) for name in USEFUL):
        return result("ok", {"ip": ip}, reason="empty")
    data["ip"] = data.get("ip") or ip
    return result("ok", data, reason="success")


if __name__ == "__main__":
    import json
    import sys
    print(json.dumps(run(sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"), indent=2, ensure_ascii=False))
