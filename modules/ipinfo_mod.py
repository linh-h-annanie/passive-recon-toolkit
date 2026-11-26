import os
import json
import ipinfo
from dotenv import load_dotenv

load_dotenv()

def run(target: str, timeout: int = 10) -> dict:
    """
    Module thu thập thông tin GeoIP và ASN từ IPinfo.
    :param target: Địa chỉ IPv4/IPv6 mục tiêu (ví dụ: '8.8.8.8')
    :param timeout: Thời gian tối đa chờ kết nối mạng (giây)
    :return: dict chuẩn hóa theo quy ước chung của nhóm
    """
    result = {
        "module": "ipinfo",
        "status": "ok",
        "source": "ipinfo.io",
        "data": {},
        "error": None
    }

    token = os.getenv("IPINFO_TOKEN")
    if not token:
        result["status"] = "skipped"
        result["error"] = "Thieu IPINFO_TOKEN trong file .env"
        return result

    try:
        handler = ipinfo.getHandler(token, request_options={"timeout": timeout})
        details = handler.getDetails(target)
        raw = details.all

        result["data"] = {
            "ip": raw.get("ip", target),
            "hostname": raw.get("hostname"),
            "city": raw.get("city"),
            "region": raw.get("region"),
            "country": raw.get("country"),
            "loc": raw.get("loc"),         
            "org": raw.get("org"),         
            "postal": raw.get("postal"),
            "timezone": raw.get("timezone")
        }
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result



if __name__ == "__main__":
    import sys

    target_ip = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    
    res = run(target_ip)
    print(json.dumps(res, indent=2, ensure_ascii=False))