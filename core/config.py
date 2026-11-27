"""Run configuration and target validation for the Passive Recon Toolkit.

Safety rules enforced here (not in each module):
  * only a public domain name or a public IP address is accepted as a target;
  * an optional allow-list (env ALLOWED_TARGETS or --allow) restricts targets further;
  * live network use needs an explicit opt-in, demo/replay never touches the network;
  * output file names are derived from the validated target, never from raw user input.
"""
import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = ROOT / "demo_data" / "recorded_runs"
OUTPUT_DIR = ROOT / "output"

# Execution order; keys are module names, values are the attribute under `modules.`
MODULE_ORDER = ("whois", "dns", "crtsh", "shodan", "censys", "ipinfo", "apivoid", "dorks")
MODES = ("demo", "live")
LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class ConfigError(ValueError):
    """Invalid target, mode or option."""


def validate_target(raw):
    """Return ('ip'|'domain', normalized) or raise ConfigError. Never resolves or contacts anything."""
    if not isinstance(raw, str) or not raw.strip():
        raise ConfigError("target must not be empty")
    if any(ord(c) < 32 or ord(c) == 127 for c in raw):  # checked before strip(): a trailing newline is rejected too
        raise ConfigError("target must not contain control characters")
    if any(c.isspace() for c in raw.strip()):
        raise ConfigError("target must not contain spaces")
    text = raw.strip()
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        ip = None
    if ip is not None:
        if not ip.is_global:
            raise ConfigError("private, loopback or reserved IP addresses are not allowed")
        return "ip", str(ip)
    if "://" in text or "/" in text or "@" in text or ":" in text:
        raise ConfigError("give a bare domain name or IP (no URL, path, credentials or port)")
    try:
        host = text.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ConfigError("invalid domain name") from exc
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or labels[-1].isdigit() or not all(LABEL_RE.fullmatch(p) for p in labels):
        raise ConfigError("invalid domain name")
    return "domain", host


def parse_allowlist(*sources):
    """Merge comma-separated allow-list strings into a tuple of normalized domains/IPs."""
    items = []
    for src in sources:
        for part in (src or "").split(","):
            if part.strip():
                items.append(validate_target(part)[1])
    return tuple(dict.fromkeys(items))


def is_allowed(kind, value, allowlist):
    """Empty allow-list = no extra restriction. A domain entry also covers its subdomains."""
    if not allowlist:
        return True
    return any(value == item or (kind == "domain" and value.endswith("." + item)) for item in allowlist)


@dataclass
class RunConfig:
    target: str
    kind: str
    mode: str = "demo"
    allowlist: tuple = ()
    dorks_mode: str = "disabled"          # disabled | demo | live (live also needs mode=live)
    modules: tuple = MODULE_ORDER
    output_dir: Path = field(default_factory=lambda: OUTPUT_DIR)
    module_config: dict = field(default_factory=dict)


def build_config(target, mode="demo", allow=None, dorks="disabled", modules=None, output_dir=None):
    """Validate everything and return a RunConfig. Raises ConfigError on any problem."""
    if mode not in MODES:
        raise ConfigError(f"mode must be one of {MODES}")
    kind, value = validate_target(target)
    allowlist = parse_allowlist(os.environ.get("ALLOWED_TARGETS", ""), allow)
    if not is_allowed(kind, value, allowlist):
        raise ConfigError("target is not in the allow-list")
    if dorks not in ("disabled", "demo", "live"):
        raise ConfigError("dorks must be disabled, demo or live")
    if dorks == "live" and mode != "live":
        raise ConfigError("dorks=live needs mode=live")
    chosen = tuple(modules) if modules else MODULE_ORDER
    unknown = [m for m in chosen if m not in MODULE_ORDER]
    if unknown:
        raise ConfigError(f"unknown module(s): {', '.join(unknown)}")
    cfg = RunConfig(value, kind, mode, allowlist, dorks, chosen, Path(output_dir) if output_dir else OUTPUT_DIR)
    cfg.module_config = {"dorks_mode": dorks}
    return cfg
