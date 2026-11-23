# Google Hacking Database, dorking và thu thập URL bằng Python
## 1. Vai trò trong trinh sát thụ động
Trinh sát thụ động sử dụng thông tin công khai được bên khác thu thập hoặc lập chỉ mục. Với phần việc của tôi, chương trình hỏi Google thay vì gửi yêu cầu đến máy chủ đích. Cách tiếp cận này phù hợp nội dung Chương 2 của Nishant Krishna, *Python for Cybersecurity Cookbook*, BPB Online, 2024, trang 19-20 và 27-35 [1].

Kết quả phản ánh dữ liệu trong chỉ mục tìm kiếm tại thời điểm truy vấn. Chúng có thể không đầy đủ hoặc không còn cập nhật. Nếu truy cập URL để xác minh nội dung, đó là bước khác; bản demo này không thực hiện bước đó.

## 2. GHDB và dorking

GHDB là danh mục truy vấn tìm kiếm được phân loại. Các mẫu truy vấn giúp phát hiện thông tin công khai, trong đó có thông tin bị lộ ngoài ý muốn. GHDB và dork được giới thiệu ở trang 27-28 của sách [1] và tại trang giới thiệu chính thức của Exploit Database [2].

Dorking là xây dựng hoặc sử dụng truy vấn với điều kiện cụ thể để lọc kết quả. GHDB cung cấp mẫu truy vấn; Google thực thi tìm kiếm; Pagodo hỗ trợ tự động hóa danh sách truy vấn. Đây là ba vai trò khác nhau.

Trong demo này, ba truy vấn `filetype:pdf`, `filetype:docx`, `filetype:pptx` do nhóm chọn để tìm tài liệu công khai, không tuyên bố là ba mục được tải từ GHDB. Mục đích là minh họa luồng hoạt động và thu URL, không tìm dữ liệu nhạy cảm.

## 3. Toán tử dùng trong truy vấn

| Toán tử | Vai trò | Ví dụ |
|---|---|---|
| `site:` | Giới hạn domain | `site:nasa.gov` |
| `filetype:` | Lọc định dạng tệp | `filetype:pdf` |
| `"..."` | Tìm cụm từ chính xác | `"annual report"` |
| `-` | Loại trừ từ/cụm từ | `-draft` |
| `inurl:` | Điều kiện trên URL | Được minh họa ở trang sách 28, 34 |
| `intitle:` | Điều kiện trên tiêu đề | Được minh họa ở trang sách 28 |

Google hướng dẫn trực tiếp `site:`, `filetype:`, dấu ngoặc kép và dấu trừ trong tài liệu Search Help [3]. Các toán tử phải gắn liền với giá trị, ví dụ `site:nasa.gov` [3]. `inurl:`/`intitle:` ở bảng được dẫn từ sách [1]; ba dork mặc định của demo không dùng hai toán tử này.

Ví dụ truy vấn hoàn chỉnh: `site:nasa.gov filetype:pdf "annual report"`. Module tự thêm `site:` và kiểm tra domain; các biểu thức có thể tách phạm vi bằng OR hoặc `|` bị từ chối. Ngoài việc giới hạn truy vấn, chương trình còn lọc hostname của URL nhận được.

## 4. Google Dorks với Pagodo

Sách trình bày Pagodo ở trang 28-33: đọc danh sách dork, đặt domain, chạy tìm kiếm, thu URL và lưu JSON [1]. Bản demo ghim mã upstream Pagodo 2.8.0 theo commit `26fbf13ae117391a6cac8be81cef7524a1cb9dfa`, giữ nguyên nguồn và giấy phép [4].

Luồng demo:

1. Đọc 2-3 dork từ tệp và xác minh đầu vào.
2. Chạy Pagodo tuần tự từng dork, chờ ngẫu nhiên 10-15 giây giữa các dork.
3. Pagodo sử dụng yagooglesearch; lớp bao kiểm soát việc lấy trang và dừng khi có lỗi.
4. Lọc URL thuộc domain/subdomain, chuẩn hóa và loại trùng.
5. Lưu kết quả có trạng thái và thông tin nguồn để chuyển cho merger.

Lý do cần lớp bao: backend upstream có cơ chế xử lý HTTP 429 và Pagodo có thể ghi log ngoại lệ rồi tiếp tục. Bản demo yêu cầu dừng ngay và phân biệt lỗi với kết quả rỗng, nên dùng worker cô lập và transport không retry. Giữ parser thật của thư viện; không dùng fixture làm đầu ra thực nghiệm. Xem mã upstream cục bộ trong `vendor/pagodo/pagodo.py` và tài liệu yagooglesearch [4][5].

## 5. Google Search trực tiếp bằng Python

Trang 33-35 của sách sử dụng distribution `google` và hàm `googlesearch.search(..., stop=5)` [1]. Bản demo cài `google==3.0.0`, kiểm tra chữ ký có `stop`, rồi dùng hàm này để phân tích kết quả cho truy vấn riêng [6][7].

Đây là thư viện thu thập HTML, không phải Google Search API chính thức. Tên import `googlesearch` không đồng nghĩa mọi distribution có tên tương tự đều tương thích. Không sử dụng import `sympy.Q` xuất hiện thừa trong ZIP tham khảo.

## 6. So sánh hai cách

| Tiêu chí | Pagodo | Google Search trực tiếp |
|---|---|---|
| Đầu vào demo | Tệp 2-3 dork và domain | Domain và một query |
| Điểm thuận tiện | Tổ chức danh sách và kết quả dork | Tìm kiếm tùy chỉnh gọn |
| Backend | yagooglesearch 1.10.0 | google 3.0.0 |
| Giới hạn URL mặc định | 3 mỗi dork | 5 mỗi query |
| Đầu ra tích hợp | Cùng schema JSON của demo | Cùng schema JSON của demo |

## 7. Đánh giá kết quả và giới hạn

- URL khớp dork chưa chứng minh có lỗ hổng. Việc tài liệu công khai là đúng hay sai cần bối cảnh và xác minh riêng.
- Không có kết quả tìm kiếm chưa chứng minh hệ thống an toàn. Có thể tài liệu chưa được lập chỉ mục, query không phù hợp hoặc dữ liệu chưa cập nhật.
- Chỉ gắn `empty` khi parser không có URL và trang thể hiện thông báo không có kết quả rõ ràng. Trang lỗi, HTML lạ, chặn JavaScript, CAPTCHA và lỗi mạng có trạng thái riêng.
- Nhịp chờ 10-15 giây giúp giới hạn tốc độ, không bảo đảm Google chấp nhận truy vấn.
- Trong lần thử thật ngày 23/11/2026, Google chặn ở dork đầu tiên. Đây là kiểm chứng cơ chế dừng; chưa phải thực nghiệm thu URL thành công. Xem `KIEM_THU.md`.

## Tài liệu tham khảo

[1] Nishant Krishna, *Python for Cybersecurity Cookbook*, BPB Online, 2024, Chương 2, tr. 19-20, 27-35. Bản PDF người dùng cung cấp: trang PDF 45-46, 53-61; thư mục nguồn `D:\PTIT\Python cho ATTT\tailieu`.

[2] Exploit Database, [Google Hacking Database](https://www.exploit-db.com/google-hacking-database), phần giới thiệu GHDB.

[3] Google Search Help, [Refine Google searches](https://support.google.com/websearch/answer/2466433?hl=en), mục Operators; [Advanced Search](https://www.google.com/advanced_search).

[4] opsdisk, [Pagodo](https://github.com/opsdisk/pagodo), commit `26fbf13ae117391a6cac8be81cef7524a1cb9dfa`. Đã tải và đọc nguồn thực tế của commit; bản cục bộ trong `vendor/pagodo/`, metadata ở `UPSTREAM.json`.

[5] opsdisk, [yagooglesearch 1.10.0](https://pypi.org/project/yagooglesearch/1.10.0/). Đối chiếu thêm mã gói đã cài trong môi trường ảo.

[6] Mario Vilas, [google 3.0.0](https://pypi.org/project/google/3.0.0/).

[7] Mario Vilas, [googlesearch source](https://github.com/MarioVilas/googlesearch/blob/master/googlesearch/__init__.py). Đã đối chiếu chữ ký và parser với distribution 3.0.0 cài cục bộ.
