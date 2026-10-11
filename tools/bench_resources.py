"""M4: CPU/RAM của agent. Chạy 2 lần: lúc rảnh và lúc cao điểm (vd chạy bench_dns song song). ≥30 mẫu, 1 giây/mẫu.
Dùng: python bench_resources.py --pid <PID agent> [--n 30]   (cần psutil)"""
import argparse
import statistics

import psutil

ap = argparse.ArgumentParser()
ap.add_argument("--pid", type=int, required=True)
ap.add_argument("--n", type=int, default=30)
a = ap.parse_args()
p = psutil.Process(a.pid)
p.cpu_percent(None)
cpu, rss = [], []
for _ in range(a.n):
    cpu.append(p.cpu_percent(interval=1.0))
    rss.append(p.memory_info().rss / 2**20)
print(f"n={a.n}  CPU trung bình={statistics.mean(cpu):.2f}% max={max(cpu):.2f}%   RAM trung bình={statistics.mean(rss):.1f} MiB max={max(rss):.1f} MiB")
