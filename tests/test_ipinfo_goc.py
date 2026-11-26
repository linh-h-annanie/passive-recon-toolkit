import os
import ipinfo
from dotenv import load_dotenv

load_dotenv()
token = os.getenv("IPINFO_TOKEN")

print(f"[*] Dang kiem tra token...")
if not token:
    print("[-] Loi: Chua tim thay IPINFO_TOKEN trong file .env!")
    exit(1)

handler = ipinfo.getHandler(token)

target_ip = "8.8.8.8"
print(f"[*] Dang lay thong tin cho IP: {target_ip}...")

details = handler.getDetails(target_ip)

print("\n=== KET QUA IPINFO ===")
print(f"IP: {details.ip}")
print(f"City: {details.city}")
print(f"Region: {details.region}")
print(f"Country: {details.country_name}")
print(f"Location (Lat, Long): {details.loc}")
print(f"Organization / ASN: {details.org}")
print(f"Timezone: {details.timezone}")
print("======================\n")