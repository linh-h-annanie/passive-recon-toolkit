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

url = "https://api.apivoid.com/v2/ssl-info"
target_host = "google.com"

headers = {
    "X-API-Key": api_key,
    "Content-Type": "application/json"
}

payload = {
    "host": target_host
}

print(f"[*] Dang goi APIVoid kiem tra SSL cho: {target_host} (Ton 1 credit)...")
try:
    response = requests.post(url, headers=headers, json=payload, timeout=15)
    response.raise_for_status()
    data = response.json()

    print("\n=== KET QUA APIVOID SSL INFO ===")
    print(json.dumps(data, indent=2, ensure_ascii=False))
    print("===============================\n")

    with open("apivoid_ssl_sample_google.com.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print("[+] Da luu ket qua vao file apivoid_ssl_sample_google.com.json thanh cong!")

except Exception as e:
    print(f"[-] Loi khi goi APIVoid SSL: {e}")
    if 'response' in locals() and response is not None:
        print(f"Chi tiet loi: {response.text}")