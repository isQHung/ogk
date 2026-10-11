"""M4/F4: độ trễ áp dụng chính sách từ dashboard đến máy trẻ (đề: ≤ 60 giây), ≥30 mẫu.
Chạy trên máy có agent đang chạy. Dùng:
  python bench_policy_latency.py --server http://127.0.0.1:8000 --email ba@x.vn --password ... --child 1 \
      --token-file C:\\ProgramData\\OGK\\local_token --api http://127.0.0.1:47800 --n 30"""
import argparse
import statistics
import time

import httpx

ap = argparse.ArgumentParser()
ap.add_argument("--server", required=True)
ap.add_argument("--email", required=True)
ap.add_argument("--password", required=True)
ap.add_argument("--child", type=int, required=True)
ap.add_argument("--token-file", required=True)
ap.add_argument("--api", default="http://127.0.0.1:47800")
ap.add_argument("--n", type=int, default=30)
a = ap.parse_args()
c = httpx.Client(base_url=a.server)
c.post("/auth/login", json={"email": a.email, "password": a.password}).raise_for_status()
c.headers["X-CSRF-Token"] = c.cookies.get("ogk_csrf")
tok = {"X-OGK-Token": open(a.token_file).read().strip()}
pol = c.get(f"/children/{a.child}/policy").json()["policy"]
lat = []
for i in range(a.n):
    pol["quota_min_weekday"] = 60 + (i % 2)
    t = time.perf_counter()
    v = c.put(f"/children/{a.child}/policy", json=pol).json()["version"]
    while httpx.get(f"{a.api}/state", headers=tok).json()["policy_version"] != v:
        time.sleep(0.05)
        if time.perf_counter() - t > 120:
            raise SystemExit("quá 120 giây")
    lat.append(time.perf_counter() - t)
q = statistics.quantiles(lat, n=100)
print(f"n={len(lat)}  p50={q[49]:.2f}s  p95={q[94]:.2f}s  max={max(lat):.2f}s")
