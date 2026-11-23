# Mã nguồn và giấy phép bên thứ ba

`vendor/pagodo/pagodo.py` là bản nguyên trạng của dự án [opsdisk/pagodo](https://github.com/opsdisk/pagodo), commit `26fbf13ae117391a6cac8be81cef7524a1cb9dfa`, phiên bản trong mã `2.8.0`. Metadata tải nguồn nằm trong `vendor/pagodo/UPSTREAM.json`.

Giữ nguyên giấy phép GNU GPL v3 trong `vendor/pagodo/LICENSE`. Khi bàn giao hoặc phân phối bản demo có kèm Pagodo, giữ nguồn, thông tin tác giả/upstream và giấy phép tương ứng. `vendor/pagodo/__init__.py` là tệp rỗng do demo thêm để import.

Các phụ thuộc Python được cài từ PyPI vào `.venv`; phiên bản đầy đủ trong `requirements-lock.txt`. Giấy phép và metadata phân phối của từng gói được giữ trong môi trường đó. `google==3.0.0` và `yagooglesearch==1.10.0` là hai distribution khác nhau, đều cần thiết cho hai backend của demo.

Các tệp trong `reference_scan/source_files/` là bản sao từ ZIP sách do người dùng cung cấp để đối chiếu; không phải module thực thi của demo và không bị sửa trong quá trình triển khai.
