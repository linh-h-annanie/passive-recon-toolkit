import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("APIVOID_API_KEY")

print("[*] Dang kiem tra APIVoid Key...")
if not api_key:
    print("[-] Loi: Chua tim thay APIVOID_API_KEY trong file .env!")
    exit(1)

url = "https://api.apivoid.com/v2/ip-reputation"
target_ip = "8.8.8.8"

headers = {
    "X-API-Key": api_key,
    "Content-Type": "application/json"
}

payload = {
    "ip": target_ip
}

print(f"[*] Dang goi APIVoid v2 kiem tra IP: {target_ip} (Ton 1 credit)...")
try:
    response = requests.post(url, headers=headers, json=payload, timeout=15)
    response.raise_for_status()
    data = response.json()

    print("\n=== KET QUA APIVOID IP REPUTATION (V2) ===")
    print(json.dumps(data, indent=2, ensure_ascii=False))
    print("==========================================\n")

    with open("apivoid_sample_8.8.8.8.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print("[+] Da luu ket qua vao file apivoid_sample_8.8.8.8.json thanh cong!")

except Exception as e:
    print(f"[-] Loi khi goi APIVoid: {e}")
    if 'response' in locals() and response is not None:
        print(f"Chi tiet loi tu server: {response.text}")