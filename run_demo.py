"""Script chạy Demo (Live & Offline) và xuất báo cáo HTML tổng hợp cho nhóm."""
import argparse
import html
import json
import subprocess
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parent
RUNS_DIR = ROOT / "output" / "runs"
DEFAULT_TARGETS = ["example.com", "example.org"]


def find_latest_json(target: str) -> Path:
    if not RUNS_DIR.exists():
        raise FileNotFoundError(f"Chưa có thư mục {RUNS_DIR}. Hãy chạy chế độ 'live' trước.")
    files = sorted(RUNS_DIR.glob(f"{target}_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        raise FileNotFoundError(f"Chưa có dữ liệu JSON của '{target}' trong {RUNS_DIR}.")
    return files[0]


def export_html_report(data: dict, json_path: Path) -> Path:
    target = html.escape(str(data.get("target", "")))
    gen_at = html.escape(str(data.get("generated_at", "")))
    summary = data.get("summary", {})
    modules = data.get("modules", {})
    network = data.get("network", {})
    hosts = network.get("hosts", [])
    services = network.get("services", [])
    warnings = data.get("warnings", [])

    whois = modules.get("whois") or {}
    dns = modules.get("dns") or {}
    crtsh = modules.get("crtsh") or {}
    ipinfo = modules.get("ipinfo") or {}
    subdomains = crtsh.get("subdomains") or []

    host_rows = "\n".join(
        f"<tr><td>{html.escape(str(h.get('ip', '-')))}</td>"
        f"<td>{html.escape(str(h.get('org') or '-'))} ({html.escape(str(h.get('asn') or '-'))})</td>"
        f"<td>{html.escape(str(h.get('city') or '-'))}, {html.escape(str(h.get('country') or '-'))}</td>"
        f"<td>{html.escape(', '.join(map(str, h.get('ports', []))) or '-')}</td>"
        f"<td><strong>{html.escape(str(h.get('source', '-')))}</strong></td></tr>"
        for h in hosts
    ) or "<tr><td colspan='5'>Không có dữ liệu host</td></tr>"

    svc_rows = "\n".join(
        f"<tr><td>{html.escape(str(s.get('ip', '-')))}</td>"
        f"<td>{html.escape(str(s.get('port', '-')))}/{html.escape(str(s.get('transport', 'tcp')))}</td>"
        f"<td>{html.escape(str(s.get('service', '-')))}</td>"
        f"<td><strong>{html.escape(str(s.get('source', '-')))}</strong></td></tr>"
        for s in services
    ) or "<tr><td colspan='4'>Không có dữ liệu dịch vụ</td></tr>"

    sub_items = "\n".join(f"<li>{html.escape(str(s))}</li>" for s in subdomains[:20]) or "<li>Không có</li>"
    warn_items = "\n".join(f"<li>{html.escape(str(w))}</li>" for w in warnings) or "<li>Không có cảnh báo</li>"

    page = f"""<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><title>PassiveRecon Report - {target}</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 28px; color: #1f2937; line-height: 1.5; }}
  h1 {{ color: #1e3a8a; margin-bottom: 4px; }}
  h2 {{ color: #1e40af; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; margin-top: 24px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; }}
  th {{ background: #1e3a8a; color: #fff; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
</style></head><body>
<h1>PassiveRecon Toolkit — Báo cáo Tổng hợp</h1>
<p><strong>Mục tiêu:</strong> {target} | <strong>Thời gian:</strong> {gen_at} | <strong>JSON gốc:</strong> {html.escape(json_path.name)}</p>

<h2>1. Trạng thái thực thi các module</h2>
<ul>
  <li><strong>Thành công (ok):</strong> {html.escape(', '.join(summary.get('ok', [])) or 'Không có')}</li>
  <li><strong>Bỏ qua (skipped):</strong> {html.escape(', '.join(x.get('module', '') for x in summary.get('skipped', [])) or 'Không có')}</li>
  <li><strong>Lỗi (error):</strong> {html.escape(', '.join(x.get('module', '') for x in summary.get('error', [])) or 'Không có')}</li>
</ul>

<h2>2. Thông tin đăng ký, DNS &amp; Vị trí IP</h2>
<ul>
  <li><strong>Registrar (WHOIS):</strong> {html.escape(str(whois.get('registrar') or '-'))}</li>
  <li><strong>Bản ghi DNS:</strong> {html.escape(str(dns.get('records') or dns or '-'))[:220]}</li>
  <li><strong>Vị trí / ASN (IPinfo):</strong> {html.escape(str(ipinfo.get('city') or '-'))}, {html.escape(str(ipinfo.get('country') or '-'))} — {html.escape(str(ipinfo.get('org') or '-'))}</li>
  <li><strong>Subdomain tìm thấy (crt.sh):</strong> {len(subdomains)}</li>
</ul>
<ul>{sub_items}</ul>

<h2>3. Thông tin Host (Shodan &amp; Censys)</h2>
<table><tr><th>IP</th><th>Tổ chức / ASN</th><th>Vị trí</th><th>Cổng mở</th><th>Nguồn</th></tr>{host_rows}</table>

<h2>4. Cổng &amp; Dịch vụ lộ ra ngoài đã gộp (Shodan + Censys)</h2>
<table><tr><th>IP</th><th>Cổng</th><th>Dịch vụ / Banner</th><th>Nguồn đối chiếu</th></tr>{svc_rows}</table>

<h2>5. Cờ cảnh báo tự động ({len(warnings)})</h2>
<ul>{warn_items}</ul>
</body></html>"""

    out_html = json_path.with_suffix(".html")
    out_html.write_text(page, encoding="utf-8")
    return out_html


def render_terminal_demo(json_path: Path):
    data = json.loads(json_path.read_text(encoding="utf-8"))
    summary = data.get("summary", {})
    network = data.get("network", {})
    hosts = network.get("hosts", [])
    services = network.get("services", [])
    warnings = data.get("warnings", [])

    print("\n" + "=" * 76)
    print(f"DEMO KẾT QUẢ TỔNG HỢP — TARGET: {data.get('target')}")
    print(f"File JSON: {json_path.name}")
    print("=" * 76)
    print("  [OK]     :", ", ".join(summary.get("ok", [])) or "Không có")
    print("  [SKIPPED]:", ", ".join(x["module"] for x in summary.get("skipped", [])) or "Không có")
    print("  [ERROR]  :", ", ".join(x["module"] for x in summary.get("error", [])) or "Không có")

    print("\n  --- Thông tin Host (Shodan + Censys) ---")
    for h in hosts:
        print(f"  * {h.get('ip')} | {h.get('org')} ({h.get('asn')}) | "
              f"{h.get('city')}, {h.get('country')} | Nguồn: {h.get('source')}")
    if not hosts:
        print("  * Không có dữ liệu host")

    print("\n  --- Dịch vụ đã gộp & khử trùng lặp (Shodan + Censys) ---")
    print(f"  {'IP':<18} {'PORT':<10} {'SERVICE':<28} {'SOURCE'}")
    print("  " + "-" * 72)
    for s in services:
        port_col = f"{s.get('port')}/{s.get('transport', 'tcp')}"
        svc_col = str(s.get("service", "-"))[:27]
        print(f"  {str(s.get('ip')):<18} {port_col:<10} {svc_col:<28} {s.get('source')}")
    if not services:
        print("  (Không có dữ liệu dịch vụ)")

    print(f"\n  --- Cờ cảnh báo ({len(warnings)}) ---")
    for w in warnings:
        print(f"  ! {w}")

    html_path = export_html_report(data, json_path)
    print(f"\n  -> Đã xuất báo cáo HTML cho Report.pdf: {html_path}")
    print("=" * 76)


def main():
    parser = argparse.ArgumentParser(description="Script chạy Demo Live/Offline cho Nhóm 1")
    parser.add_argument("mode", choices=["live", "offline"], help="live: gọi API thật; offline: đọc JSON đã lưu")
    parser.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS, help="Danh sách domain mục tiêu")
    parser.add_argument("--dorks", choices=["off", "demo", "live"], default="demo", help="Chế độ chạy Google Dorks")
    args = parser.parse_args()

    for target in args.targets:
        if args.mode == "live":
            print(f"\n>>> Đang chạy thu thập dữ liệu LIVE cho: {target} ...")
            subprocess.run([sys.executable, str(ROOT / "main.py"), target, "--dorks", args.dorks], check=True)
        json_path = find_latest_json(target)
        render_terminal_demo(json_path)


if __name__ == "__main__":
    main()
