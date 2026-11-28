# Application of Python in Passive Reconnaissance in the Field of Information Security

Course project on Python applications for **SEC1302 - Python for Information Security**, Semester 1, Academic Year 2026-2027.
Posts and Telecommunications Institute of Technology (PTIT).

---

## Project Identity

* **Topic:** #01: Application of Python in Passive Reconnaissance in the Field of Information Security
* **Team:** G1 ()
* **Instructor / Supervisor:** ThS. Phan Nghĩa Hiệp (`hieppn@ptithcm.edu.vn`)

### Project Team \& Personnel

|Role / Student ID|Full Name|GitHub / Affiliation|Email|
|-|-|-|-|
|**Instructor**|ThS. Phan Nghĩa Hiệp|Giảng viên hướng dẫn|`hieppn@ptithcm.edu.vn`|
|**N25DCAT079**|Đặng Quang Huy|[@Kurookani](https://github.com/Kurookani)|`n25dcat079@student.ptithcm.edu.vn`|
|**N25DCAT086**|Hồ Thị Trúc Linh|[@linh-h-annanie](https://github.com/linh-h-annanie)|`n25dcat086@student.ptithcm.edu.vn`|
|**N25DCAT099**|Thân Lê Nhật Quang|[@nhatquangthl](https://github.com/nhatquangthl)|`n25dcat099@student.ptithcm.edu.vn`|
|**N25DCAT097**|Trần Thiên Hoàng Quân|[@lailawan](https://github.com/lailawan)|`n25dcat097@student.ptithcm.edu.vn`|
|**N25DCAT100**|Thái Mỹ Quyên|[@cybercyber123132](https://github.com/cybercyber123132)|`n25dcat100@student.ptithcm.edu.vn`|

---

## Tổng quan & Triết lý Trinh sát Bị động

**Passive Recon Toolkit** là giải pháp phần mềm toàn diện nhằm tự động hóa quy trình thu thập thông tin tình báo an ninh mạng nguồn mở (OSINT) trên phạm vi tên miền và địa chỉ IP công khai.

### Triết lý Trinh sát Bị động 
Công cụ tuân thủ nghiêm ngặt nguyên lý không tác động trực tiếp tới hạ tầng của mục tiêu:
1. **Không quét cổng (Zero Port Scanning):** Không gửi gói tin TCP SYN/Connect tới máy chủ mục tiêu.
2. **Không thăm dò dịch vụ (Zero Active Probing):** Không gửi HTTP request hay payload khai thác vào ứng dụng của mục tiêu.
3. **Khai thác qua trung gian độc lập:**
   - Dữ liệu đăng ký tên miền công cộng từ các tổ chức quản lý (WHOIS Protocol TCP/43).
   - Hệ thống máy chủ tên miền đệ quy (Recursive DNS Caches).
   - Nhật ký minh bạch chứng chỉ SSL/TLS công khai (Certificate Transparency Logs - RFC 6962).
   - Các công cụ tìm kiếm thiết bị mạng toàn cầu (Shodan, Censys).
   - Cơ sở dữ liệu định vị địa lý và số hiệu mạng (IPinfo GeoIP & ASN).
   - Nền tảng đánh giá danh tiếng địa chỉ IP (APIVoid Threat Intelligence).
   - Chỉ mục tìm kiếm công cộng (Google Dorking & Pagodo).

---

## Cấu trúc mã nguồn Repository


```text
.
├── main.py                     
├── requirements.txt            
├── .env.example                
├── .gitignore                  
├── README.md                   
│
├── core/
│   ├── config.py
│   └── merger.py               
│
├── modules/                    
│   ├── whois_mod.py            
│   ├── dns_mod.py              
│   ├── crtsh_mod.py            
│   ├── shodan_mod.py           
│   ├── censys_mod.py           
│   ├── ipinfo_mod.py           
│   ├── apivoid_mod.py         
│   ├── dorks_mod.py           
│   └── google_search_client.py 
│
├── vendor/
│   └── pagodo/                 
│       ├── pagodo.py          
│       ├── UPSTREAM.json       
│       └── LICENSE             
│
├── tests/
│   ├── test_api_modules.py                 
│   ├── test_whois_dns_crtsh.py 
│   ├── test_shodan_censys.py   
│   ├── test_ipinfo_goc.py      
│   ├── test_apivoid_goc.py     
│   ├── test_apivoid_ssl.py     
│   ├── test_dorks_mod.py      
│   ├── test_merge_all.py       
│   └── bangiaominhchunggsgd/   
│
└── output/                     
    ├── apivoid_sample_8.8.8.8.json
    ├── apivoid_ssl_sample_google.com.json
    ├── example.com_shodan_censys.json
    ├── example.net_shodan_censys.json
    ├── example.net.*
    └── example.com.*
                   
```

---

## Yêu cầu hệ thống & Cài đặt

### 1. Yêu cầu môi trường
- **Hệ điều hành:** Linux, macOS hoặc Windows 10/11.
- **Python:** Phiên bản `Python 3.10` trở lên.

### 2. Các bước cài đặt

**Bước 1:** Clone mã nguồn từ GitHub:
```bash
git clone https://github.com/linh-h-annanie/passive-recon-toolkit.git
cd passive-recon-toolkit
```

**Bước 2:** Khởi tạo môi trường ảo (`venv`):
- Trên **Linux / macOS**:
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```
- Trên **Windows (PowerShell)**:
  ```powershell
  python -m venv .venv
  .venv\Scripts\Activate.ps1
  ```

**Bước 3:** Cài đặt các gói phụ thuộc qua `requirements.txt`:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```
---

## Tài liệu tham khảo

1. **Nishant Krishna**, *Python for Cybersecurity Cookbook*, Packt Publishing, 2020.
2. **RFC 3912:** *WHOIS Protocol Specification*, IETF.
3. **RFC 1034 & RFC 1035:** *Domain Names - Concepts and Facilities / Implementation and Specification*, IETF.
4. **RFC 6962:** *Certificate Transparency*, IETF.
5. **RFC 1918 & RFC 4193:** *Address Allocation for Private Internets / Unique Local IPv6 Unicast Addresses*.
6. **Shodan Developer Documentation:** [https://developer.shodan.io/api](https://developer.shodan.io/api)
7. **Censys Search API Documentation:** [https://search.censys.io/api](https://search.censys.io/api)
8. **IPinfo API Documentation:** [https://ipinfo.io/developers](https://ipinfo.io/developers)
9. **APIVoid API Reference:** [https://www.apivoid.com/api/](https://www.apivoid.com/api/)
10. **Pagodo (Passive Google Dork):** [https://github.com/opsdisk/pagodo](https://github.com/opsdisk/pagodo)

---
