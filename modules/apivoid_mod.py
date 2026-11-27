import json
import time
from pathlib import Path

from modules.common import BadResponse, classify_exception, clean_ip, load_env_key, make_result, read_json_limited, redact

URL = "https://api.apivoid.com/v2/ip-reputation"
DEMO_FILE = Path(__file__).resolve().parent.parent / "demo_data" / "apivoid_ip_reputation_8.8.8.8.sample.json"
SOURCE = "APIVoid"
RISK_NOTE = "risk_score is computed by APIVoid; its method has not been verified by the team"


def result(status, data=None, error=None, reason=None, source=SOURCE):
    return make_result("apivoid", source, status, data, error, reason)


def dig(obj, *path):
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def normalize(raw, ip):
    return {
        "ip": raw.get("ip") or ip,
        "risk_score": dig(raw, "risk_score", "result"),
        "risk_score_note": RISK_NOTE,
        "is_vpn": dig(raw, "anonymity", "is_vpn"),
        "is_proxy": dig(raw, "anonymity", "is_proxy"),
        "is_tor": dig(raw, "anonymity", "is_tor"),
        "is_hosting": dig(raw, "anonymity", "is_hosting"),
        "detections": dig(raw, "blacklists", "detections"),
        "engines_count": dig(raw, "blacklists", "engines_count"),
        "asn": dig(raw, "asn", "asn"),
        "org": dig(raw, "asn", "org"),
    }


def demo_result(requested):
    try:
        raw = json.loads(DEMO_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return result("error", error="Demo sample file is missing or unreadable", reason="demo_unavailable")
    data = normalize(raw, "8.8.8.8")
    data.update({"demo": True, "requested_target": requested,
                 "demo_note": "Saved APIVoid response for 8.8.8.8, replayed offline. It is NOT a lookup of the requested target."})
    return result("ok", data, reason="demo", source="APIVoid (DEMO sample file, no network)")


def parse_retry_after(headers):
    try:
        return max(0, int(str(headers.get("Retry-After", "")).strip()))
    except (ValueError, AttributeError):
        return None


def run(target, config=None):
    cfg = config if isinstance(config, dict) else {}
    mode = cfg.get("apivoid_mode", "live")
    if mode not in ("live", "demo"):
        return result("error", error="apivoid_mode must be 'live' or 'demo'", reason="invalid_config")
    if mode == "demo":
        return demo_result(target if isinstance(target, str) else None)

    key = load_env_key("APIVOID_API_KEY", cfg)
    if not key:
        return result("skipped", error="Missing APIVOID_API_KEY", reason="no_key")
    ip, problem = clean_ip(target)
    if problem == "needs_ip":
        return result("skipped", error="APIVoid IP reputation needs an IP address; pass an IP, e.g. from the dns module", reason=problem)
    if problem == "non_public_ip":
        return result("skipped", error="Private, loopback or reserved IP: public targets only", reason=problem)
    if problem:
        return result("error", error="Invalid target: expected a public IP address", reason=problem)

    import requests
    read_timeout = cfg.get("apivoid_timeout", 15)
    if not isinstance(read_timeout, (int, float)) or isinstance(read_timeout, bool) or not 0 < read_timeout <= 60:
        read_timeout = 15
    headers = {"X-API-Key": key, "Content-Type": "application/json", "Accept": "application/json",
               "User-Agent": "PassiveReconToolkit/1.0"}
    last = ("error", "error")
    for attempt in range(2):
        try:
            with requests.post(URL, headers=headers, json={"ip": ip}, timeout=(5, read_timeout),
                               allow_redirects=False, stream=True) as response:
                code = response.status_code
                if code == 429:
                    retry = parse_retry_after(response.headers)
                    data = {"retry_after_seconds": retry} if retry is not None else {}
                    return result("error", data, "APIVoid rate limit or credit quota reached (HTTP 429)", "rate_limited")
                if code in (401, 403):
                    return result("error", error=f"APIVoid rejected the key (HTTP {code})", reason="auth_error")
                if code >= 500:
                    last = (f"APIVoid server error (HTTP {code})", f"http_{code}")
                elif code != 200:
                    return result("error", error=f"Unexpected HTTP {code} from APIVoid", reason=f"http_{code}")
                else:
                    raw = read_json_limited(response)
                    return result("ok", normalize(raw, ip), reason="success")
        except BadResponse as exc:
            return result("error", error=f"Unusable APIVoid response: {exc}", reason="bad_response")
        except Exception as exc:
            reason = classify_exception(exc)
            last = (redact(f"{type(exc).__name__}: {exc}", key)[:300], reason)
            if reason not in ("timeout", "network_error"):
                break
        if attempt == 0:
            time.sleep(1)
    return result("error", error=last[0], reason=last[1])


if __name__ == "__main__":
    import sys
    print(json.dumps(run(sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"), indent=2, ensure_ascii=False))
