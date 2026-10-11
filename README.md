# OpenGuard Kids – PoC

*Công cụ đồng hành, không phải phần mềm theo dõi lén.* Agent Windows + máy chủ FastAPI + bảng điều khiển phụ huynh.

```
server/     FastAPI + SQLite + SQLAlchemy (xác thực, chính sách ký, sự kiện, báo cáo, lệnh khẩn qua WebSocket)
agent/      OGK-Agent: ogk/ (enforcer, dnsproxy, appctl, runner, tray, winadapter), service.py, agent.py, web/
dashboard/  index.html (phụ huynh) · today.html (màn hình minh bạch cho trẻ; bản sao ở agent/web/)
tests/      45 test: unit server, unit agent, tích hợp (server thật + agent thật)
tools/      bench_dns, bench_resources, bench_policy_latency (số đo M4)
scripts/    make_cert.sh (TLS tự ký cho lab)
docs/       PRIVACY.md, PRIVACY_TRE_EM.md, THREATMODEL.md, AI_USAGE.md, BaoCaoKyThuatMang.md
```

## Cài và chạy (≈15 phút)
**Server** (Windows/Linux, Python 3.11+)
```
cd server && pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000        # http://127.0.0.1:8000
```
Có TLS: `scripts/make_cert.sh <IP>` → `OGK_COOKIE_SECURE=1 uvicorn main:app --ssl-keyfile server.key --ssl-certfile server.crt`.
Biến môi trường: `OGK_DB`, `OGK_KEY_DIR` (khóa ký + khóa AES-GCM; hoặc `OGK_DATA_KEY` base64 32 byte), `OGK_RETENTION_DAYS`.

**Phụ huynh:** mở dashboard → Đăng ký (mật khẩu ≥10 ký tự) → Đăng nhập → *Thêm con* → *Tạo mã ghép đôi*.

**Máy trẻ** (Windows 10/11, tài khoản của trẻ KHÔNG thuộc Administrators; cài bằng PowerShell quản trị)
```
cd agent && pip install -r requirements.txt
python agent.py enroll --server https://<IP>:8000 --code <MÃ> --ca-cert server.crt
python agent.py run --no-lock --dns-port 5353 --block-port 8080      # thử ở chế độ console, không khóa máy thật
# Triển khai thật:
python service.py --startup auto install && sc failure OGKAgent reset= 86400 actions= restart/5000/restart/5000/restart/5000
net start OGKAgent        # service dùng cổng 53/80 và đổi DNS hệ thống về 127.0.0.1
python agent.py tray      # đặt vào Startup của tài khoản trẻ (biểu tượng khay luôn hiển thị)
```
Gỡ hợp pháp: `python agent.py uninstall --email <email phụ huynh>` (nhập mật khẩu ngay trên máy trẻ; có ghi nhật ký) rồi `python service.py remove`.

## Kiểm thử
```
pip install -r server/requirements.txt -r agent/requirements.txt
pytest tests -q          # 45 test
```

## Trạng thái so với đề
| Hạng mục | Trạng thái |
|---|---|
| F1 quota ngày thường/cuối tuần, lịch 7×48, đếm giờ thực (bỏ qua lúc rảnh >5 phút), cảnh báo 10/5/1 phút + ân hạn 60s, chống chỉnh đồng hồ | Có (test) |
| F1 ngân sách theo nhóm ứng dụng; thưởng giờ | **Chưa** |
| F2 chặn app theo SHA-256, giải thích lý do; DNS proxy + nhóm + SafeSearch + DoH/canary; chặn DNS ngoài | Có (logic có test; phần Windows chưa thử) |
| F2 bảng phân loại ≥200 mục (212) | Có – **cần nhóm rà soát từng mục**; không chứa tên miền người lớn (nhóm “không phù hợp” dùng miền giả `*.ogk-test.test`; muốn dùng danh sách chặn thật, nạp qua `categories.csv`) |
| F2 proxy HTTP(S)/WFP | **Chưa** (hạng mục “có thì tốt”) |
| F3 lược đồ sự kiện cố định, báo cáo, màn hình trẻ, lưu 90 ngày, xóa dữ liệu, CSV | Có. **Chưa:** xuất PDF, quy tắc 20-20-20 |
| F4 1:n:m, chính sách ký + phiên bản, nhật ký kiểm toán trẻ xem được, lệnh khẩn WebSocket, ngoại tuyến + idempotency, gỡ cài đặt hợp pháp | Có. **Chưa:** tạm nghỉ của phụ huynh |
| F5 Argon2id, khóa tạm, CSRF, TLS + ghim, access/refresh token, AES-GCM 1 trường, chống IDOR | Có. **Chưa:** TOTP, header bảo mật, mã hóa thêm trường |
| Báo cáo chính BaoCao.docx (20–30 trang), slide, video demo, số đo M3/M4/M5, ảnh Wireshark | **Chưa – nhóm phải thực hiện** |

## Việc nhóm cần làm trước khi nộp
1. Chạy và kiểm tra **trên máy Windows sạch**: service, tray, khóa phiên, DNS 127.0.0.1, luật firewall (phần này chưa được thử).
2. Đối chiếu văn bản pháp luật gốc; điền `docs/PRIVACY.md` (hạn lưu nhật ký kiểm toán), `AI_USAGE.md`.
3. Làm các phép đo M3–M5; điền `docs/BaoCaoKyThuatMang.md`; **quyết định và bảo vệ** fail-open/fail-closed.
4. Rà soát bảng phân loại và danh sách miễn chặn (`agent/ogk/data/exempt.txt`, hiện có `tongdai111.vn`, `moet.gov.vn` – cần kiểm chứng và thêm cổng trường).
