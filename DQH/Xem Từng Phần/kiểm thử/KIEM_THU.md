# Kết quả kiểm tra ngày 23/11/2026

## Môi trường

Windows, Python 3.13.7 trong `.venv`. Pagodo 2.8.0 theo commit trong `vendor/pagodo/UPSTREAM.json`. Các phiên bản gói cài thực tế nằm trong `requirements-lock.txt`. `pip check` báo không có phụ thuộc hỏng.

## Offline

Đã chạy 17 kiểm tra bằng unittest, tất cả đạt. Log: `output/offline_tests.txt`.

Các hành vi đã kiểm tra:

- Domain hợp lệ và từ chối URL/IP/cổng/domain sai.
- Ghép `site:` và từ chối biểu thức có thể tách phạm vi.
- Lọc hostname chính xác/subdomain, loại domain gần giống, chuẩn hóa URL và loại trùng.
- Dry-run không tạo worker hoặc chờ, JSON đọc lại đúng.
- Từ chối thư mục ghi ngoài `DQH/demo`.
- Phân biệt kết quả rỗng, lỗi mạng và thiếu phụ thuộc.
- Dừng các dork còn lại sau khi bị chặn.
- Chờ trong khoảng 10-15 giây giữa các dork (kiểm tra bằng mock sleep).
- URL duy nhất vẫn giữ đủ truy vấn nguồn.
- Transport không gửi request tới URL đích; không theo redirect consent.
- HTTP 429/CAPTCHA dừng ngay, không retry; HTML lạ không thành `empty`.
- Parser thật của google/Pagodo-yagooglesearch trích được URL từ HTML giả lập.
- Hai backend thật nhận `empty` khi có thông báo rõ và không nuốt tín hiệu `blocked`.

HTML và URL `example.com` trong các kiểm tra là fixture offline. Chúng không phải kết quả thu được từ Google. Gói google phát cảnh báo `findAll` đã deprecated từ BeautifulSoup; đây là cảnh báo ở nguồn bên thứ ba, kiểm tra vẫn đạt.

## Dry-run

Đã chạy cả hai chế độ với `nasa.gov`, không gửi HTTP:

- Dorks: `output/20261123T044206_8482efb6/results.json`.
- Search: `output/20261123T044206_24db92f4/results.json`.
- Tóm tắt: `output/dry_run_summary.json`.

Dorks gồm `site:nasa.gov filetype:pdf`, `site:nasa.gov filetype:docx`, `site:nasa.gov filetype:pptx`. Mỗi kết quả có `status=dry_run`, `urls=[]`, không giả định đã tìm thấy tài liệu.

## Lần chạy thật

Người dùng đã xác nhận dùng `nasa.gov` để tìm tài liệu công khai qua Google.

1. Lần chạy trong sandbox lúc 11:42:09 giờ Việt Nam gặp lỗi DNS. Dork đầu có `network_error`, không coi là kết quả rỗng. Bằng chứng: `output/20261123T044209_8bcdb417/results.json`.
2. Sau khi có quyền truy cập mạng, lần chạy lúc 11:42:25-11:42:39 giờ Việt Nam đã gửi 2 HTTP request cho dork PDF (trang chủ Google và trang tìm kiếm). Transport phát hiện điều kiện chặn CAPTCHA/consent/JavaScript ở phản hồi tìm kiếm. Kết quả: `blocked`, không URL.
3. Dork DOCX/PPTX thành `skipped`. `run_demo.py` bỏ qua chế độ Search. Không đổi proxy, user-agent, dịch vụ hoặc dùng trình duyệt để vượt điều kiện chặn.

Bằng chứng lần đã kết nối mạng:

- `output/20261123T044225_01c05d1c/results.json`.
- `output/20261123T044225_01c05d1c/query_1/response.json`.
- `output/live_run_summary.json`.

Trạng thái `blocked` hiện gộp các trường hợp CAPTCHA, consent và JavaScript; lần thử lưu thông báo tổng quát này, không khẳng định đã xác định chính xác loại nào trong ba loại. Không lưu toàn bộ HTML hoặc cookie của Google.

## Kết luận thực nghiệm

Mã, cài đặt, API, JSON, dry-run và parser offline đã kiểm tra. Thử thật xác nhận chương trình kết nối tới Google và dừng khi gặp trang chặn. **Chưa xác minh khả năng thu URL thành công từ Google thật; chế độ Search chưa được thử live sau khi Pagodo bị chặn.** Không dùng các fixture để lấp phần kết quả còn thiếu.

Chạy lại kiểm tra offline theo README. Chỉ thực hiện một lần thử live mới khi phù hợp, không lặp tự động hoặc tìm cách vượt chặn. Kết quả Google có thể thay đổi; đây là ghi nhận của phiên chạy này.
