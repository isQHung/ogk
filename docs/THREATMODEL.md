# THREATMODEL.md – STRIDE và checklist ASVS

Trạng thái: **Có** = đã hiện thực và có test · **Một phần** = làm nửa chừng · **Chấp nhận** = biết rõ, không chặn được · **Chưa** = chưa làm.

## 1. STRIDE (13 mối đe dọa)
| # | Loại | Mối đe dọa | Biện pháp trong mã | Trạng thái / rủi ro còn lại |
|---|---|---|---|---|
| 1 | S | **Trẻ đoán/đánh cắp mật khẩu phụ huynh** (kịch bản “chính trẻ là kẻ tấn công”) | Argon2id; ≥10 ký tự; khóa 15 phút sau 5 lần sai; rate limit theo IP; cookie HttpOnly/SameSite; CSRF | Có. Chưa có TOTP, chưa kiểm tra mật khẩu bị lộ |
| 2 | S | Máy chủ giả (MITM) đẩy chính sách dễ dãi | TLS + ghim chứng chỉ (`--ca-cert`); chính sách ký Ed25519, agent kiểm tra chữ ký mỗi lần nạp; từ chối phiên bản cũ hơn (chống replay) | Có (đã thử TLS + ghim; test `i2`) |
| 3 | T | Trẻ sửa tệp cache/chính sách cục bộ | Chữ ký được xác minh lại khi nạp; thư mục ProgramData đặt ACL (`protect_home`) | Một phần: ACL chỉ hiệu lực trên Windows và **chưa thử trên Windows thật**; tài khoản Administrators vẫn sửa được |
| 4 | T | **Chỉnh đồng hồ hệ thống** để kéo dài giờ | Giờ tin cậy = giờ máy chủ + đồng hồ đơn điệu; sàn “không lùi”; lệch >120 giây ghi sự kiện `clock_tamper` | Có (test: lùi 3 giờ, quota không tăng) |
| 5 | R | Phụ huynh/Trẻ chối việc đổi luật | Nhật ký kiểm toán: ai, lúc nào, IP, giá trị cũ → mới; trẻ xem được (không kèm IP) | Có. Nhật ký chưa chống sửa bằng mật mã (hash chain) |
| 6 | I | **IDOR**: gia đình A đọc dữ liệu gia đình B | Kiểm tra sở hữu trong câu truy vấn (`own_child`, join theo `parent_id`) | Có (test cho 7 endpoint) |
| 7 | I | Nghe lén dữ liệu trong mạng LAN | TLS 1.2+ | Có khi chạy TLS (lab dùng chứng chỉ tự ký) |
| 8 | I | Lộ dữ liệu khi mất tệp DB | `subject` mã hóa AES-GCM, khóa từ biến môi trường/tệp riêng; token chỉ lưu dạng băm | Một phần: mới mã hóa 1 trường; tên trẻ, email lưu rõ |
| 9 | D | Dò mã ghép đôi / dồn tải đăng nhập | Mã 8 ký tự (32^8), hết hạn 10 phút, dùng 1 lần; rate limit | Có |
| 10 | D | **Trẻ kết thúc agent / dừng service** | Service Recovery Options khởi động lại; tick vẫn khóa theo cache | Một phần: chưa thử trên Windows; Safe Mode, USB boot **chấp nhận** (cần BitLocker/mật khẩu BIOS – ngoài phạm vi) |
| 11 | E | Trẻ có quyền Administrator → gỡ/sửa mọi thứ | Yêu cầu cài đặt: tài khoản trẻ không thuộc Administrators | Chấp nhận: nếu trẻ là admin thì không chặn được |
| 12 | E | **Vòng DNS** (DoH, DoT, đổi DNS, VPN, IP trực tiếp) | Chặn điểm cuối DoH + canary NXDOMAIN; luật firewall chặn 53/853 (trừ upstream); xem M3 | Một phần – VPN/IP trực tiếp **chấp nhận** |
| 13 | S/E | **Stalkerware**: dùng sản phẩm theo dõi người lớn | Không có chế độ ẩn; biểu tượng khay + thông báo khởi động bắt buộc; thiếu tray quá 3 phút thì agent **tự tạm dừng kiểm soát** (`require_tray`); không thu nội dung/URL/vị trí; chỉ ghép đôi bằng mã do tài khoản phụ huynh tạo | Một phần: không xác minh được người dùng máy là trẻ em. **Phạm vi hợp pháp:** chỉ dùng cho con chưa thành niên của chính mình, có thông báo cho con. Mọi dùng khác là vi phạm |

## 2. Checklist ASVS v4 mức 1 (22 mục – *số hiệu mục nhóm cần đối chiếu bản gốc 4.0.3*)
| # | Yêu cầu (tóm tắt) | Trạng thái | Chỗ trong mã |
|---|---|---|---|
| 1 | Mật khẩu ≥12 ký tự (V2.1.1) | Một phần – đề yêu cầu 10 | `register` |
| 2 | Cho phép mật khẩu dài, không cắt (V2.1.2) | Một phần – chưa đặt trần chống DoS | `register` |
| 3 | Kiểm tra mật khẩu bị lộ (V2.1.7) | Chưa | – |
| 4 | Chống dò mật khẩu tự động (V2.2.1) | Có | `login`, `RateLimiter` |
| 5 | Băm mật khẩu có muối, thuật toán khuyến nghị (V2.4.1) | Có (Argon2id) | `ph` |
| 6 | Phiên mới sau đăng nhập (V3.2.1) | Có | `login` |
| 7 | Cookie HttpOnly/Secure/SameSite (V3.4.x) | Có (`Secure` bật bằng `OGK_COOKIE_SECURE=1`) | `login` |
| 8 | Đăng xuất hủy phiên phía server (V3.3.1) | Có | `logout`, test |
| 9 | Hết hạn phiên (V3.3.2) | Có (12 giờ) | `SESSION_HOURS` |
| 10 | Kiểm soát truy cập thực thi ở server (V4.1.1) | Có | `parent_required`, `device_required` |
| 11 | Chống IDOR (V4.2.1) | Có | `own_child`, test |
| 12 | Chống CSRF cho thao tác ghi (V4.2.2) | Có (double-submit) | `parent_w` |
| 13 | Kiểm tra đầu vào bằng schema (V5.1.x) | Một phần – pydantic, chưa có giới hạn cho mọi trường | `main.py` models |
| 14 | Truy vấn tham số hóa (V5.3.4) | Có (SQLAlchemy) | toàn bộ |
| 15 | Mã hóa đầu ra chống XSS (V5.3.3) | Có (dashboard dùng `textContent`) – **chưa thử trên trình duyệt thật** | `dashboard/index.html` |
| 16 | Không để bí mật trong URL (V8.3.1) | Có (token ở header/cookie) | – |
| 17 | Chống cache dữ liệu nhạy cảm (V8.2.1) | Chưa | – |
| 18 | TLS cho mọi kết nối (V9.1.1) | Có (lab) | `scripts/make_cert.sh` |
| 19 | Cấu hình TLS mạnh/tối thiểu TLS 1.2 (V9.1.2) | Một phần – dùng mặc định uvicorn | – |
| 20 | Header bảo mật (CSP, nosniff…) (V14.4.x) | Chưa | – |
| 21 | Phụ thuộc có phiên bản cố định, quét lỗ hổng (V14.2.1) | Chưa | `requirements.txt` chưa pin |
| 22 | Không ghi mật khẩu/token vào log (V7.1.1) | Một phần – chưa rà soát toàn bộ | – |
