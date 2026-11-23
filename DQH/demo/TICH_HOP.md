# Bàn giao Cho Quyên nè

API nằm trong `recon.py`: `run_recon(domain, mode='dorks', query='filetype:pdf', dorks_file=None, limit=None, dry_run=False, output_dir=None)`.

Ví dụ dưới đây là hướng dẫn cho chương trình tích hợp sau này; bản demo không sửa `main.py` ở gốc:

```python
from DQH.demo.recon import run_recon

report = run_recon('nasa.gov', mode='dorks', dry_run=True)
for item in report['unique_urls']:
    print(item['url'], item['queries'])
```

Khi chạy từ gốc repository, Python hỗ trợ namespace package nên không cần thêm `__init__.py` bên ngoài `DQH/demo`. Nếu chương trình nhóm dùng vị trí khác, đưa gốc repository vào đường dẫn import của chương trình nhóm.

Chạy với Python trong môi trường `DQH/demo/.venv` khi gọi thật; worker sử dụng chính `sys.executable` của caller. Nếu caller dùng Python chưa cài phụ thuộc, kết quả có thể là `dependency_error`. Dry-run không cần phụ thuộc bên thứ ba.

Hàm đồng bộ, phải gọi tuần tự. Khoảng chờ 10-15 giây giữa dork do module xử lý; nếu caller gọi nhiều phiên/mode liên tiếp thì caller cần chờ tương ứng giữa các phiên. Khi gặp `blocked`, dừng tác vụ thay vì gọi mode khác để thử lại.

## Dữ liệu cho merger

- `report['source']`: `pagodo` hoặc `google`.
- `report['domain']`: domain đã chuẩn hóa.
- `report['status']`: trạng thái toàn phiên.
- `report['results']`: bằng chứng theo từng truy vấn; không bỏ `status`, `error`, `started_at`, `completed_at`.
- `report['unique_urls']`: danh sách URL duy nhất cùng mảng `queries` truy vết.
- `report['output_file']`: đường dẫn tuyệt đối của JSON thực tế.
- `report['dry_run']`: luôn kiểm tra trước khi đưa kết quả vào báo cáo thực nghiệm.

URL được chuẩn hóa hostname, bỏ cổng mặc định và fragment; giữ scheme, path, query string. HTTP/HTTPS hoặc query string khác nhau vẫn là URL khác. Domain đích và subdomain được chấp nhận; domain chỉ chứa tên gần giống bị loại. Không thực hiện DNS resolve hay tải URL đích.

Đầu vào không hợp lệ hoặc lỗi ghi file làm hàm raise `ValueError`/`OSError`. Lỗi truy vấn được lưu ở `results[n]['status']` và `error`; trạng thái toàn phiên thành `error`. Không chuyển lỗi thành danh sách rỗng rồi coi là thành công.

`output_dir` nếu cung cấp phải resolve về bên trong `DQH/demo`. Giữ toàn bộ thư mục `vendor/pagodo` và giấy phép khi bàn giao. Không copy riêng `recon.py` vì còn cần `_worker.py`, `dorks.txt` và vendor.

## Điều đã kiểm tra và việc còn lại

Hai backend đã đọc HTML giả lập bằng parser thật. Dry-run cả hai chế độ đã chạy. Lần Google thật qua Pagodo trên `nasa.gov` bị chặn ở truy vấn đầu; Search thật được bỏ qua theo quy tắc dừng. Người 1 cần giữ thông tin giới hạn này trong báo cáo thực nghiệm, không ghi rằng nhóm đã tìm thấy URL/lỗ hổng từ lần chạy đó.
