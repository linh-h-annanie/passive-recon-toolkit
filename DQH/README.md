# Demo của Huy - Google Dorks và Google Search

Phần việc của Đặng Quang Huy trong passive-recon-toolkit. Mã nguồn, môi trường ảo và kết quả chạy nằm trong DQH/demo.
Tài liệu được phân loại trong DQH/Xem Từng Phần.

Chỉ chạy chương trình trong thư mục DQH/demo.
Thư mục DQH/Xem Từng Phần dùng để đọc tài liệu đã phân loại.

## Trạng thái kiểm tra ngày 23/11/2026

- Python 3.13.7 trên Windows; đã cài và kiểm tra phụ thuộc bằng `pip check`.
- Kiểm tra offline dùng HTML giả lập để xác minh parser thật của cả hai thư viện. Dữ liệu này không phải kết quả Google thật.
- Dry-run hai chế độ trên `nasa.gov` thành công, tạo JSON có trạng thái `dry_run`.
- Đã thử thật bằng Pagodo trên `nasa.gov` sau khi người dùng đồng ý. Google trả trang bị nhận diện là CAPTCHA/consent/JavaScript. Truy vấn đầu có trạng thái `blocked`; hai truy vấn tiếp theo và chế độ Search bị bỏ qua. Chưa xác minh thu URL thành công từ Google thật.
- Xem [Kết quả kiểm thử](<Xem Từng Phần/kiểm thử/KIEM_THU.md>) và `demo/output/live_run_summary.json` để đối chiếu bằng chứng.
## Cấu trúc

```text
DQH/
├── README.md
├── demo/
│   ├── recon.py
│   ├── _worker.py
│   ├── run_demo.py
│   ├── dorks.txt
│   ├── requirements.txt
│   ├── requirements-lock.txt  
│   ├── TICH_HOP.md
│   ├── vendor/pagodo/
│   ├── tests/test_recon.py
│   └── output/              # Tự tạo khi chạy
└── Xem Từng Phần/
    ├── kiểm thử/
    ├── lý thuyết báo cáo/
    ├── nguồn và giấy phép/
    └── Phụ thuộc/
```
`.venv`, `.cache`, `output` và bytecode được bỏ qua bởi `.gitignore` cục bộ. Tài liệu kiểm thử ghi lại đường dẫn bằng chứng nhưng các kết quả thực thi không tự đi vào Git.

## Cài đặt bằng PowerShell

Mở PowerShell trong `DQH/demo`:

```powershell
Set-Location -LiteralPath "D:\PTIT\Python cho ATTT\passive-recon-toolkit\DQH\demo"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip --cache-dir .cache/pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -m pip check
```

Không cần activate môi trường hoặc thay đổi execution policy. Môi trường `.venv` hiện đã được tạo trên máy này. Nếu cài mới, toàn bộ packages nằm trong `.venv`, cache trong `.cache/pip`.

Phụ thuộc trực tiếp đã kiểm tra:

| Thành phần | Phiên bản / định danh |
|---|---|
| Python | 3.13.7 |
| Pagodo | 2.8.0, commit `26fbf13ae117391a6cac8be81cef7524a1cb9dfa` |
| `google` | 3.0.0; import `googlesearch`, hỗ trợ `stop=` |
| `yagooglesearch` | 1.10.0; backend của Pagodo |
| `requests` | 2.32.5 |
| `beautifulsoup4` | 4.13.5 |

Không cài thêm `googlesearch-python` vào môi trường này vì có thể xung đột namespace `googlesearch`. Pagodo đã được lưu trong `vendor`, không cần clone lúc chạy. Không sử dụng import `sympy` thừa từ mã mẫu.

## Chạy dry-run

```powershell
.\.venv\Scripts\python.exe -B run_demo.py --domain nasa.gov --dry-run
```

Không gửi HTTP và không cần import thư viện bên thứ ba. Có thể dùng Python hệ thống cho dry-run:

```powershell
python -B recon.py dorks --domain nasa.gov --dry-run
python -B recon.py search --domain nasa.gov --query 'filetype:pdf "annual report"' --dry-run
```

Mỗi chế độ tạo thư mục riêng trong `output`. `run_demo.py` ghi thêm `output/dry_run_summary.json`.

## Chạy thật

chạy trên domain `nasa.gov` cho demo tìm tài liệu công khai này.

```powershell
.\.venv\Scripts\python.exe -B run_demo.py --domain nasa.gov
```

Hoặc chạy riêng một chế độ khi cần, không chạy đồng thời:

```powershell
.\.venv\Scripts\python.exe -B recon.py dorks --domain nasa.gov --limit 3
.\.venv\Scripts\python.exe -B recon.py search --domain nasa.gov --query 'filetype:pdf "annual report"' --limit 5
```

`run_demo.py` tự chờ 10-15 giây giữa hai chế độ. Khi chạy các lệnh riêng, người vận hành cũng cần chờ giữa các lần gọi. Nếu lần trước bị Google chặn, dừng phiên demo, không dùng chế độ khác để thử vượt chặn.

Mặc định `dorks.txt` chứa `filetype:pdf`, `filetype:docx`, `filetype:pptx`; module thêm `site:<domain>` trước mỗi truy vấn. File tùy chọn được truyền bằng `--dorks-file`, phải có 2-3 dòng truy vấn khác nhau (bỏ qua dòng trống và chú thích `#`). Đường dẫn file tương đối được tính từ `DQH/demo`, không phải thư mục PowerShell hiện tại.

`--limit` nhận 1-10; mặc định 3 cho dorks, 5 cho search. Query tùy chọn không được chứa `site:`, `OR`, `|`, ngoặc hoặc ký tự điều khiển; giới hạn này giữ phạm vi truy vấn đơn giản và dễ kiểm tra. Chỉ truyền tên miền, không truyền URL/IP/cổng.

## Cách xử lý và vị trí ghi file

1. Kiểm tra domain, ghép truy vấn có `site:`, đọc tối đa ba dork.
2. Với mỗi truy vấn thật, chạy worker riêng với cwd là `output/<run>/query_<n>`.
3. Pagodo vẫn đọc file dork, tạo truy vấn, gọi backend và xuất JSON/URL. Lớp bao thay phần lấy trang bằng transport giới hạn, giữ parser và luồng Pagodo.
4. Google Search dùng parser thật của `google==3.0.0`, thay `get_page` bằng cùng transport để kiểm soát timeout và phản hồi chặn.
5. Lọc URL về đúng domain/subdomain, loại fragment và URL trùng. Gom URL toàn phiên, giữ danh sách truy vấn nguồn.
6. Lưu `results.json`; API trả lại cùng từ điển đó.

Khoảng chờ giữa các dork là ngẫu nhiên 10-15 giây. Một truy vấn có thể cần nhiều HTTP request (trang chủ, trang tìm kiếm, phân trang). Transport cũng giới hạn tốc độ HTTP; phân trang của yagooglesearch có thể chờ lâu hơn. Tối đa 4 HTTP request/truy vấn, timeout mỗi request 20 giây, timeout worker 180 giây. Không có retry tự động, proxy rotation hoặc xử lý vượt CAPTCHA/consent. Chỉ cho gửi HTTP tới trang chủ/tìm kiếm Google, không theo redirect và không mở URL đích.

Log import-time của yagooglesearch và các file Pagodo đều nằm trong thư mục worker. Cookie jar Google được đặt cục bộ, transport chỉ dùng cookie trong bộ nhớ. TLS được xác minh.

## Kết quả JSON

Các trường chính: `source`, `domain`, `dry_run`, `started_at`, `completed_at`, `status`, `results`, `unique_urls`, `output_file`.

- `results`: mỗi phần tử có `source`, `domain`, `query`, `urls`, thời điểm, `status`, `error`.
- `unique_urls`: mỗi phần tử có `url`, `queries`, giúp loại trùng toàn phiên mà vẫn giữ nguồn.
- Thời điểm trong JSON là UTC ISO 8601. Giờ Việt Nam bằng UTC + 7.

| Trạng thái truy vấn | Ý nghĩa |
|---|---|
| `dry_run` | Chỉ tạo truy vấn, chưa gửi HTTP |
| `success` | Parser có URL và có URL hợp lệ thuộc domain |
| `empty` | Parser không có URL, trang có thông báo không tìm thấy rõ ràng |
| `blocked` | HTTP 403/429, CAPTCHA, consent hoặc yêu cầu JavaScript |
| `network_error` | Lỗi kết nối/DNS/TLS/timeout ở tầng HTTP |
| `parse_error` | HTML không được nhận diện hoặc không trích được kết quả chắc chắn |
| `dependency_error` | Thiếu hoặc sai gói thư viện |
| `scope_filtered` | Parser có URL nhưng không URL nào hợp lệ thuộc phạm vi |
| `http_error`, `redirect`, `request_limit` | HTTP khác, redirect hoặc đạt giới hạn request |
| `timeout`, `backend_error` | Worker quá hạn hoặc lỗi backend |
| `skipped` | Chưa chạy vì truy vấn trước đã lỗi |

Trạng thái toàn phiên là `dry_run`, `success`, `empty` hoặc `error`. Khi lỗi ở một truy vấn, dừng phần còn lại; kết quả trước lỗi vẫn được giữ. CLI exit 0 cho dry-run/success/empty, exit 1 cho lỗi thực thi, exit 2 cho đầu vào không hợp lệ.

## Kiểm tra offline

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Có thể chạy bằng đường dẫn tuyệt đối từ thư mục khác; các đường dẫn đầu ra vẫn dựa trên vị trí mã. Không cần quyền ghi vào thư mục làm việc của caller.

## Giới hạn và xử lý lỗi thường gặp

- `dependency_error`: dùng đúng `.venv\Scripts\python.exe`, cài lockfile, kiểm tra `pip check`.
- `network_error`: xác minh DNS/kết nối và quyền truy cập mạng. Lỗi DNS không phải kết quả tìm kiếm rỗng.
- `blocked`: dừng lần chạy, ghi nhận trong báo cáo; chương trình không giải CAPTCHA hay đổi proxy/user-agent để vượt chặn.
- `parse_error`: HTML có thể thay đổi. Cần kiểm tra parser trên fixture cập nhật trước khi kết luận.
- Thư viện thu thập HTML không phải Google Search API chính thức. Việc parser chạy được offline không bảo đảm Google sẽ trả kết quả có thể phân tích trong môi trường thật.
- URL khớp dork chưa chứng minh có lỗ hổng. Không có kết quả tìm kiếm chưa chứng minh hệ thống an toàn.

Lý thuyết nằm trong [Lý thuyết](<Xem Từng Phần/lý thuyết báo cáo/LY_THUYET.md>).
Cách gọi từ chương trình nhóm nằm trong [Hướng dẫn tích hợp](demo/TICH_HOP.md).