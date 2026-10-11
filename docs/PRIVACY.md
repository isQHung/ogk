# PRIVACY.md – Bảng dữ liệu · mục đích · thời hạn lưu · ai xem được

> Nguyên tắc: trường nào không giải thích được mục đích thì **không có** trong lược đồ (NT2).
> Căn cứ đối chiếu theo đề: Luật Trẻ em 2016 (Điều 21), Nghị định 13/2023/NĐ-CP. *Nhóm tự đối chiếu văn bản gốc trước khi nộp.*

## 1. Dữ liệu về hoạt động (bảng `events`)
| Trường | Ví dụ | Mục đích | Lưu bao lâu | Ai xem |
|---|---|---|---|---|
| ts | thời điểm sự kiện | Vẽ biểu đồ theo ngày/tuần | 90 ngày, tự xóa (`purge_old`) | Phụ huynh; trẻ (qua màn hình “Hôm nay em đã dùng gì”) |
| device_id, child_id | số nguyên | Biết sự kiện của máy/trẻ nào (1 phụ huynh : n trẻ : m máy) | 90 ngày | Phụ huynh |
| type | `app_stop`, `blocked_domain`… (9 loại cố định) | Phân loại để báo cáo | 90 ngày | Phụ huynh; trẻ |
| subject | `minecraft.exe`, `hcmus.edu.vn` | Biết app/miền nào dùng nhiều – **chỉ tên app hoặc tên miền cấp hai**, server từ chối chuỗi chứa `/ ? # &` hay khoảng trắng; **mã hóa AES-GCM khi lưu** | 90 ngày | Phụ huynh; trẻ |
| duration_sec | 120 | Tính thời lượng sử dụng | 90 ngày | Phụ huynh; trẻ |
| policy_id | số phiên bản luật | Biết sự kiện xảy ra dưới luật nào (giải thích được) | 90 ngày | Phụ huynh |
| uid | UUID | Khóa chống trùng khi đồng bộ ngoại tuyến | 90 ngày | Không hiển thị |

## 2. Dữ liệu khác
| Dữ liệu | Mục đích | Lưu bao lâu | Ai xem |
|---|---|---|---|
| Email phụ huynh, băm mật khẩu (Argon2id) | Đăng nhập | Đến khi xóa tài khoản | Chỉ chủ tài khoản (mật khẩu không ai xem được) |
| Tên và tuổi của trẻ | Hiển thị; chọn chính sách mặc định theo độ tuổi | Đến khi phụ huynh xóa | Phụ huynh; tên hiện trên máy trẻ |
| Tên máy, `fingerprint` (băm SHA-256 của tên máy + MAC) | Nhận diện máy khi ghép đôi, thu hồi | Đến khi thu hồi/gỡ máy | Phụ huynh |
| `last_seen`, `quota_used_sec`, `clock_skew` | Hiển thị trạng thái máy; phát hiện chỉnh đồng hồ | Ghi đè mỗi 60 giây (chỉ giá trị mới nhất) | Phụ huynh |
| Yêu cầu của trẻ (xin giờ, báo chặn nhầm) + phản hồi | Quyền có tiếng nói của trẻ (NT3) | 90 ngày | Phụ huynh; trẻ |
| Nhật ký kiểm toán (ai, lúc nào, IP, giá trị cũ/mới) | Giải trình mọi thay đổi luật (NT5) | **Chưa có hạn tự xóa – nhóm cần quyết định** (đề xuất: giữ cùng vòng đời hồ sơ của trẻ) | Phụ huynh (đủ); trẻ (không kèm IP) |
| Chính sách đã ký | Áp dụng luật | Phiên bản hiện hành; bản cũ nằm trong nhật ký | Phụ huynh; trẻ (qua nhật ký thay đổi) |

## 3. Dữ liệu KHÔNG thu thập
Nội dung tin nhắn/email/tài liệu · URL đầy đủ hoặc đường dẫn · tiêu đề cửa sổ · phím gõ · ảnh chụp màn hình · vị trí · dữ liệu gửi tới bên thứ ba.
(Truy vấn DNS được chuyển tiếp tới máy chủ DNS upstream do phụ huynh chọn như mọi truy vấn DNS thông thường; agent không gửi dữ liệu nào khác ra ngoài.)

## 4. Quyền của gia đình
* **Đồng ý của cha mẹ**: ghi nhận khi phụ huynh tạo mã ghép đôi (`/children/{id}/enroll-code`) và agent dùng mã đó (`/enroll`, trường `consent_parent_id`, nhật ký `device_enrolled`).
* **Xóa dữ liệu**: nút “Xóa toàn bộ dữ liệu của con tôi” (`DELETE /children/{id}/data`) xóa trên server và gửi lệnh `wipe_cache` để agent xóa hàng đợi sự kiện.
* **Hạn chế lưu trữ**: tác vụ `purge_old` chạy lúc khởi động và mỗi 24 giờ.
