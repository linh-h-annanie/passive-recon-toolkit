import argparse
import importlib
import ipaddress
import json
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from core import config as cfgmod
from core.merger import merge_all

ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = ROOT / "output" / "runs"
DEMO_DIR = ROOT / "demo_data" / "recorded_runs"

# Execution order; dorks is last because it is slow (10-15 s pause between queries).
# Modules are imported lazily so that one missing third-party library only skips that module.
MODULE_NAMES = ("whois", "dns", "crtsh", "shodan", "censys", "ipinfo", "apivoid", "dorks")
IP_ONLY = {"ipinfo", "apivoid"}  # modules that accept an IP only, not a domain
CONTRACT = {"module", "status", "source", "data", "error", "timestamp"}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def to_ip(target):
    """Return the target's public IP (resolving a domain), or None if it cannot be determined or is not public."""
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(target))
        except (OSError, ValueError):
            return None
    return str(ip) if ip.is_global else None


def error_result(name, message, reason="error", status="error"):
    """Result following the shared contract, used when a module cannot run or crashes."""
    return {
        "module": name, "status": status, "source": name, "data": {"reason": reason},
        "error": message, "timestamp": now_iso(),
    }


def check_contract(name, res):
    """Accept only a dict with exactly the six contract keys and a known status."""
    if not isinstance(res, dict):
        return error_result(name, f"module returned {type(res).__name__}, expected dict", "bad_module_result")
    if set(res) != CONTRACT or res.get("status") not in ("ok", "skipped", "error"):
        return error_result(name, "module result breaks the six-key contract", "bad_module_result")
    return res


def run_module(name, target, config):
    """Import and run one module; no failure of a module may stop the whole run."""
    try:
        mod = importlib.import_module(f"modules.{name}_mod")
    except Exception as exc:  # e.g. a third-party library is not installed
        return error_result(name, f"{type(exc).__name__}: {exc}", "dependency_missing", "skipped")
    try:
        res = mod.run(target, config)
    except Exception as exc:
        return error_result(name, f"{type(exc).__name__}: {exc}")
    return check_contract(name, res)


def load_demo(target):
    """Replay a recorded run. The file is found by listing the demo folder, never by joining user input."""
    for path in DEMO_DIR.glob("*.json"):
        if path.stem == target:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("target") == target and isinstance(data.get("modules"), list):
                return [check_contract(str(m.get("module")), m) for m in data["modules"]], data.get("generated_at")
    return None, None


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Passive reconnaissance toolkit",
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument("target", help="public domain or public IP, e.g. example.org")
    parser.add_argument("--mode", choices=cfgmod.MODES, default="demo",
                        help="demo (default): replay recorded data offline; live: query real sources")
    parser.add_argument("--i-allow-network", action="store_true", help="required for --mode live")
    parser.add_argument("--allow", help="comma-separated allow-list of domains/IPs (also env ALLOWED_TARGETS)")
    parser.add_argument("--skip", nargs="*", default=[], choices=list(MODULE_NAMES),
                        metavar="MODULE", help="modules to skip")
    parser.add_argument("--dorks", choices=["off", "demo", "live"], default="off",
                        help="off: do not run (default); demo: synthetic data; live: query Google (needs --mode live)")
    return parser.parse_args(argv)


def run(args):
    """Validate, run (or replay) and merge. Raises ConfigError for any rejected input."""
    wanted = tuple(m for m in MODULE_NAMES if m not in args.skip)
    cfg = cfgmod.build_config(args.target, args.mode, args.allow,
                              "disabled" if args.dorks == "off" else args.dorks, wanted)
    target = cfg.target
    if cfg.mode == "demo":
        results, observed_at = load_demo(target)
        if results is None:
            raise cfgmod.ConfigError("no recorded demo run for this target; use --mode live --i-allow-network")
        results = [r for r in results if r["module"] in wanted]
        return merge_all(target, results, mode="demo", observed_at=observed_at)

    config = {"dorks_mode": "disabled" if args.dorks == "off" else args.dorks}
    results = []
    for name in wanted:
        print(f"[*] {name} ...", end=" ", flush=True)
        value = to_ip(target) if name in IP_ONLY else target
        if value is None:
            res = error_result(name, "could not determine a public IP for the target", "needs_ip", "skipped")
        else:
            res = run_module(name, value, config)
        print(res.get("status"))
        results.append(res)
    return merge_all(target, results, mode="live")


def main(argv=None):
    args = parse_args(argv)
    try:
        if args.mode == "live" and not args.i_allow_network:
            raise cfgmod.ConfigError("live mode needs --i-allow-network")
        merged = run(args)
    except cfgmod.ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", merged["target"])
    out_file = OUTPUT_DIR / f"{safe_name}_{merged['mode']}_{datetime.now():%Y%m%d_%H%M%S}.json"
    out_file.write_text(json.dumps(merged, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    summary = merged["summary"]
    print(f"\n=== Summary ({merged['mode']} mode) ===")
    print("Succeeded:", summary["ok"])
    print("Skipped  :", [x["module"] for x in summary["skipped"]])
    print("Errors   :", [x["module"] for x in summary["error"]])
    print("Warnings :", len(merged["warnings"]))
    print("Saved to :", out_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
