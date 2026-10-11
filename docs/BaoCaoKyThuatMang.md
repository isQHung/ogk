# Báo cáo kỹ thuật hệ thống và mạng (khung M1–M6)

> **Quy ước:** phần *thiết kế/phân tích* đã được soạn theo mã nguồn. Mọi ô ghi **[NHÓM ĐO/THỬ]** là kết quả thực nghiệm mà nhóm phải tự thực hiện trên máy Windows thật rồi điền – không điền số ước đoán. Xuất ra PDF trước khi nộp.

## M1. Luồng gói tin khi trẻ mở trang bị chặn
```
Trình duyệt → stub resolver Windows → 127.0.0.1:53 (DNS proxy của agent)
   → decide_domain(): miễn chặn? DoH/canary? luật tên miền? nhóm bị chặn?
        ├─ chặn : trả A=127.0.0.1 (AAAA rỗng) → trình duyệt vào 127.0.0.1:80 → trang giải thích (lý do + ai đặt luật)
        ├─ DoH  : NXDOMAIN
        ├─ SafeSearch : CNAME → forcesafesearch.google.com + A
        └─ cho phép : chuyển tiếp upstream (UDP; TCP cũng được lắng nghe) → trả lời nguyên vẹn
```
**[NHÓM ĐO/THỬ]** ảnh chụp Wireshark (`udp.port == 53`) cho 1 truy vấn bị chặn và 1 truy vấn được phép; chú thích từng gói.
Lưu ý để giải thích khi vấn đáp: trang HTTPS bị chặn sẽ hiện **lỗi chứng chỉ** (agent không làm MITM TLS) – thông báo giải thích được hiển thị thêm qua tray (NT4).

## M2. So sánh phương án chặn
| Tiêu chí | Tệp hosts | DNS proxy cục bộ (**chọn**) | Proxy HTTP(S) | Bộ lọc WFP |
|---|---|---|---|---|
| Độ chính xác | Thấp: không wildcard, phải liệt kê từng tên | Cao ở mức tên miền (kèm toàn bộ tên miền con) | Cao nhất (theo đường dẫn) nhưng cần giải mã TLS | Theo IP/cổng, tên miền kém |
| Chặn HTTPS | Có (theo tên) | Có (theo tên, không cần giải mã) | Chỉ khi MITM TLS (cài CA riêng – xâm phạm riêng tư) | Có (theo IP) |
| Chi phí hiện thực | Rất thấp | Trung bình (dnslib, ~150 dòng) | Cao | Rất cao (driver/API) |
| Khả năng bị vượt | Rất dễ (sửa tệp nếu có quyền; app dùng DoH bỏ qua) | Vượt được bằng DoH/VPN/IP trực tiếp → cần các biện pháp M3 | Khó hơn nếu ép proxy, nhưng đổi cài đặt trình duyệt vẫn vượt được | Khó vượt nhất, nhưng IP CDN đổi liên tục gây chặn nhầm |
| Ảnh hưởng hiệu năng | Không | Rất nhỏ (xem M4) | Đáng kể | Nhỏ |
**Vì sao chọn DNS proxy:** cân bằng giữa độ chính xác theo tên miền, không đụng vào nội dung mã hóa (phù hợp nguyên tắc tối thiểu dữ liệu và triết lý minh bạch), chi phí vừa tầm 4 tuần; hạn chế của nó được thừa nhận và đối phó một phần ở M3.

## M3. Phân tích đường vòng
| # | Kỹ thuật | Mô tả | Đối phó trong sản phẩm | Kết quả thử thực tế |
|---|---|---|---|---|
| 1 | Đổi DNS thủ công (vd 8.8.8.8) | Trẻ sửa cài đặt card mạng | `--system-dns` đặt lại DNS; luật firewall chặn 53/853 ra ngoài (trừ upstream của agent) | **[NHÓM ĐO/THỬ]** |
| 2 | DNS-over-HTTPS | Trình duyệt tự dùng DoH | NXDOMAIN cho canary `use-application-dns.net` và danh sách điểm cuối DoH (`data/doh_endpoints.txt`); khuyến nghị chính sách trình duyệt tắt DoH. Giới hạn: DoH tới IP cố định hoặc máy chủ chưa có trong danh sách | **[NHÓM ĐO/THỬ]** bật DoH trên Chrome, ghi lại |
| 3 | DNS-over-TLS | Cổng 853 | Luật firewall chặn 853 | **[NHÓM ĐO/THỬ]** |
| 4 | VPN/proxy công cộng | Mã hóa toàn bộ lưu lượng | **Chấp nhận rủi ro**: DNS proxy không thấy; chỉ giảm bằng chặn ứng dụng VPN theo SHA-256 và chặn tên miền nhà cung cấp VPN phổ biến | **[NHÓM ĐO/THỬ]** |
| 5 | Truy cập bằng địa chỉ IP | Gõ thẳng IP | **Chấp nhận**: DNS proxy không thấy tên miền; WFP/Proxy sẽ khắc phục (hạng mục “có thì tốt”) | **[NHÓM ĐO/THỬ]** |
| 6 | Safe Mode | Khởi động chế độ an toàn, service không chạy | Service chạy cả trong Safe Mode có mạng chỉ khi cấu hình `SafeBoot`; **chấp nhận** nếu không cấu hình – cần BitLocker/mật khẩu quản trị | **[NHÓM ĐO/THỬ]** |
| 7 | Khởi động từ USB | Bỏ qua hệ điều hành | **Chấp nhận** – ngoài phạm vi phần mềm (mật khẩu BIOS, thứ tự boot) | – |
| 8 | Tài khoản Windows khác | Đăng nhập tài khoản chưa bị giới hạn | Agent là service toàn máy (không theo tài khoản); đồng thời chính sách tài khoản: trẻ không có quyền tạo tài khoản mới | **[NHÓM ĐO/THỬ]** |
| 9 | Kết thúc tiến trình/dừng service | Task Manager, `sc stop` | Tài khoản trẻ không phải Administrator thì không dừng được service; Service Recovery khởi động lại; thiếu agent thì sau thời gian chính sách đệm vẫn áp dụng khi agent chạy lại | **[NHÓM ĐO/THỬ]** |
| 10 | Chỉnh đồng hồ | Lùi giờ để kéo dài quota | Đồng hồ đơn điệu + giờ máy chủ + sàn không lùi; test tự động đã qua | Test tự động: `test_clock_rewind_does_not_add_quota_and_is_detected`; **[NHÓM ĐO/THỬ]** lùi giờ thật trên Windows |

## M4. Đo hiệu năng (≥30 mẫu/phép đo)
Dùng `tools/bench_resources.py`, `tools/bench_dns.py`, `tools/bench_policy_latency.py`. Ghi rõ máy (CPU/RAM/OS), phương pháp, số mẫu.
| Phép đo | Rảnh | Cao điểm | Ghi chú |
|---|---|---|---|
| CPU agent (%) | **[NHÓM ĐO]** | **[NHÓM ĐO]** | cao điểm = chạy `bench_dns.py` song song |
| RAM agent (MiB) | **[NHÓM ĐO]** | **[NHÓM ĐO]** | |
| Độ trễ DNS p50/p95 – không agent | **[NHÓM ĐO]** | | |
| Độ trễ DNS p50/p95 – có agent | **[NHÓM ĐO]** | | |
| Độ trễ áp dụng chính sách (đề: ≤60 giây; lệnh khẩn ≤5 giây) | **[NHÓM ĐO]** | | Trong test tích hợp (localhost, Linux) lệnh khẩn qua WebSocket < 5 giây và đổi chính sách < 10 giây – **không dùng làm số đo chính thức** |

## M5. Khả năng chịu lỗi
| Kịch bản | Hành vi mong đợi (theo thiết kế) | Hành vi thực tế / thời gian phục hồi |
|---|---|---|
| Mất mạng | Agent dùng chính sách đệm, tiếp tục đếm giờ, xếp hàng sự kiện; khi có mạng đồng bộ theo lô, khóa chống trùng; DNS proxy trả SERVFAIL nếu upstream không tới được | Test tích hợp `i3` (hàng đợi + idempotency) đã qua; **[NHÓM THỬ]** trên Windows |
| Server ngừng | Như trên; tray hiển thị trạng thái; sau N ngày (`expiry_days`=7) áp dụng chế độ hết hạn: **`open`** (nới giới hạn thời gian, vẫn lọc nội dung) hoặc **`closed`** (giữ chính sách cũ) | **[NHÓM QUYẾT ĐỊNH và BẢO VỆ khi vấn đáp]** – mặc định đang là `open` để trẻ không bị khóa khỏi bài tập khi nhà mất mạng lâu; `closed` an toàn hơn về kiểm soát nhưng có thể khóa nhầm |
| Agent bị kết thúc | Service Recovery Options khởi động lại sau 5 giây | **[NHÓM ĐO]** thời gian phục hồi |

## M6. Đồng bộ thời gian
* Giờ tin cậy = `server_time` (mỗi heartbeat) + (`time.monotonic()` hiện tại − `monotonic` lúc đồng bộ) → chỉnh đồng hồ hệ thống không ảnh hưởng quota (`enforcer.TimeSource`).
* “Sàn” `floor` được lưu định kỳ: nếu khởi động lại sau khi lùi giờ, thời gian không thấp hơn lần cuối đã biết.
* Ngưỡng cảnh báo: |đồng hồ hệ thống − giờ tin cậy| > 120 giây → sự kiện `quota_warning` với `subject=clock_tamper` (chọn tái sử dụng loại có sẵn trong lược đồ cố định của đề), và `clock_skew` hiển thị trên dashboard.
* Giới hạn: trước lần đồng bộ đầu tiên sau khi khởi động, agent dựa vào đồng hồ hệ thống (có sàn bảo vệ).
