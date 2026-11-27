"""Passive Recon Toolkit - điểm chạy chính: gọi các module, gộp kết quả, lưu JSON."""
import argparse
import inspect
import ipaddress
import socket
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from core.merger import merge_all
from modules import (apivoid_mod, censys_mod, crtsh_mod, dns_mod,
                     dorks_mod, ipinfo_mod, shodan_mod, whois_mod)

OUTPUT_DIR = Path(__file__).resolve().parent / "output" / "runs"

# dorks để cuối vì chậm (nghỉ 10-15 giây giữa các truy vấn)
MODULES = {
    "whois": whois_mod,
    "dns": dns_mod,
    "crtsh": crtsh_mod,
    "shodan": shodan_mod,
    "censys": censys_mod,
    "ipinfo": ipinfo_mod,
    "apivoid": apivoid_mod,
    "dorks": dorks_mod,
}

IP_ONLY = {"ipinfo"}  # module chỉ nhận IP, không nhận domain


def to_ip(target):
    """Trả về IP của mục tiêu (nếu là domain thì phân giải), hoặc None nếu không được."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except OSError:
        return None


def error_result(name, message):
    """Kết quả lỗi đúng 'hợp đồng' chung, dùng khi một module sập bất ngờ."""
    return {
        "module": name, "status": "error", "source": name, "data": {},
        "error": message, "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def run_module(name, mod, target, config):
    try:
        # một số module (ví dụ ipinfo_mod) không có tham số config
        if "config" in inspect.signature(mod.run).parameters:
            res = mod.run(target, config)
        else:
            res = mod.run(target)
    except Exception as exc:
        return error_result(name, f"{type(exc).__name__}: {exc}")
    if not isinstance(res, dict):
        return error_result(name, f"Module trả về {type(res).__name__}, cần dict")
    return res


def parse_args():
    parser = argparse.ArgumentParser(description="Passive reconnaissance toolkit")
    parser.add_argument("target", help="domain hoặc IP, ví dụ: example.org")
    parser.add_argument("--skip", nargs="*", default=[], choices=list(MODULES),
                        metavar="MODULE", help="các module muốn bỏ qua")
    parser.add_argument("--dorks", choices=["off", "demo", "live"], default="off",
                        help="off: không chạy (mặc định); demo: dữ liệu giả; live: gọi Google thật")
    return parser.parse_args()


def main():
    args = parse_args()
    config = {} if args.dorks == "off" else {"dorks_mode": args.dorks}

    results = []
    for name, mod in MODULES.items():
        if name in args.skip:
            continue
        print(f"[*] {name} ...", end=" ", flush=True)
        value = to_ip(args.target) if name in IP_ONLY else args.target
        if value is None:
            res = error_result(name, "Không xác định được IP của mục tiêu")
            res["status"] = "skipped"
        else:
            res = run_module(name, mod, value, config)
        print(res.get("status"))
        results.append(res)

    merged = merge_all(args.target, results)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", args.target)
    out_file = OUTPUT_DIR / f"{safe_name}_{datetime.now():%Y%m%d_%H%M%S}.json"
    out_file.write_text(
        json.dumps(merged, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )

    summary = merged["summary"]
    print("\n=== Tóm tắt ===")
    print("Thành công:", summary["ok"])
    print("Bỏ qua    :", [x["module"] for x in summary["skipped"]])
    print("Lỗi       :", [x["module"] for x in summary["error"]])
    print("Cảnh báo  :", len(merged["warnings"]))
    print("Đã lưu    :", out_file)


if __name__ == "__main__":
    main()