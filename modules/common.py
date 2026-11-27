import ipaddress
import json
import os
import re
import socket
from datetime import datetime, timezone
from pathlib import Path

MAX_RESPONSE_BYTES = 1024 * 1024
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class BadResponse(Exception):
    """The remote answer was too large, not JSON, or not the expected shape."""


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_env_key(name, config=None):
    """Key lookup order: config dict, environment, project .env. Never logged or returned in results."""
    if isinstance(config, dict):
        value = config.get(name) or config.get(name.lower())
        if value:
            return str(value).strip()
    value = os.getenv(name)
    if value:
        return value.strip()
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                if key.strip() == name:
                    return val.strip().strip('"').strip("'")
    return ""


def clean_ip(target):
    """Return (ip_string, None) for a clean IP literal, else (None, reason_code).

    Rejects non-strings, empty values, control characters/newlines, URLs, ports, paths, domains (reason needs_ip)
    and non-public addresses (reason non_public_ip).
    """
    if not isinstance(target, str) or not target.strip():
        return None, "invalid_target"
    text = target.strip()
    if CONTROL_CHARS.search(text) or len(text) > 64:
        return None, "invalid_target"
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        looks_like_domain = re.fullmatch(r"(?=.{1,253}$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}", text)
        return None, "needs_ip" if looks_like_domain else "invalid_target"
    if not address.is_global:
        return None, "non_public_ip"
    return str(address), None


def redact(text, *secrets):
    text = str(text)
    for secret in secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, "***")
    return text


def classify_exception(exc):
    """Map an exception to a short reason code: timeout, rate_limited, auth_error, http_<code>, network_error, error."""
    status = getattr(getattr(exc, "response", None), "status_code", None)
    name = type(exc).__name__.lower()
    if isinstance(exc, (TimeoutError, socket.timeout)) or "timeout" in name or "timedout" in name:
        return "timeout"
    if status == 429 or "quota" in name or "ratelimit" in name or "toomanyrequests" in name:
        return "rate_limited"
    if status in (401, 403):
        return "auth_error"
    if isinstance(status, int):
        return f"http_{status}"
    if "connection" in name or isinstance(exc, OSError):
        return "network_error"
    return "error"


def read_json_limited(response, max_bytes=MAX_RESPONSE_BYTES):
    """Read a streamed response up to max_bytes and require a JSON object."""
    body = bytearray()
    for chunk in response.iter_content(65536):
        body.extend(chunk)
        if len(body) > max_bytes:
            raise BadResponse(f"response larger than {max_bytes // 1024} KiB")
    try:
        data = json.loads(bytes(body))
    except ValueError as exc:
        raise BadResponse("response is not valid JSON") from exc
    if not isinstance(data, dict):
        raise BadResponse("response JSON is not an object")
    return data


def make_result(module, source, status, data=None, error=None, reason=None):
    """The team's six-key contract. The finer reason code lives in data['reason'] so existing consumers keep working."""
    payload = dict(data or {})
    if reason:
        payload["reason"] = reason
    return {"module": module, "status": status, "source": source, "data": payload, "error": error, "timestamp": now_iso()}
