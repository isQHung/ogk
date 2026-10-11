# AI_USAGE.md – Khai báo sử dụng công cụ AI

| Mục | Nội dung |
|---|---|
| Công cụ | Claude (Anthropic), qua giao diện chat |
| Phần do AI soạn | Bản nháp toàn bộ mã trong `/server`, `/agent`, `/dashboard`, `/tests`, `/tools`, `/scripts`; bản nháp các tài liệu `PRIVACY.md`, `PRIVACY_TRE_EM.md`, `THREATMODEL.md`, `BaoCaoKyThuatMang.md` |
| Đã kiểm chứng bằng cách nào | 45 test tự động (20 unit server, 19 unit agent, 6 tích hợp với server uvicorn thật + agent thật + WebSocket) chạy trong môi trường **Linux**; thử TLS tự ký + ghim chứng chỉ; kiểm tra cú pháp JS của dashboard |
| **Chưa** kiểm chứng | Windows Service, tray, `WTSDisconnectSession`, `netsh`/firewall, ACL `icacls`, `GetLastInputInfo`; giao diện trên trình duyệt thật/điện thoại; mọi số đo hiệu năng (M4); thử nghiệm các đường vòng (M3); kịch bản chịu lỗi thực tế (M5); danh sách tên miền phân loại (cần rà soát từng mục) |
| Văn bản pháp luật | AI không được dùng làm nguồn trích dẫn; nhóm phải tự đối chiếu văn bản gốc |
| Phần nhóm đã sửa/viết thêm | *(nhóm điền: tệp nào, sửa gì, vì sao)* |
| Sinh viên giải thích được | *(mỗi thành viên điền các phần mình sẵn sàng bảo vệ khi vấn đáp)* |
