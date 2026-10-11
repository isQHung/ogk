"""M4: độ trễ phân giải DNS p50/p95 – trực tiếp tới upstream và qua proxy của agent (≥30 mẫu mỗi phép đo).
Dùng: python bench_dns.py --proxy 127.0.0.1:53 --upstream 1.1.1.1:53 --n 60   (cần: pip install dnslib)"""
import argparse
import statistics
import time

from dnslib import DNSRecord

DOMAINS = ["hcmus.edu.vn", "wikipedia.org", "khanacademy.org", "vnexpress.net", "python.org",
           "olm.vn", "scratch.mit.edu", "duolingo.com", "example.com", "w3schools.com"]


def measure(addr, n):
    host, port = addr.split(":")
    out = []
    for i in range(n):
        q = DNSRecord.question(DOMAINS[i % len(DOMAINS)], "A")
        t = time.perf_counter()
        q.send(host, int(port), timeout=3)
        out.append((time.perf_counter() - t) * 1000)
    return out


def pct(xs, p):
    return statistics.quantiles(xs, n=100)[p - 1]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", default="127.0.0.1:53")
    ap.add_argument("--upstream", default="1.1.1.1:53")
    ap.add_argument("--n", type=int, default=60)
    a = ap.parse_args()
    measure(a.upstream, 10)  # làm nóng bộ nhớ đệm của upstream
    for name, addr in (("Không agent (upstream)", a.upstream), ("Có agent (proxy)", a.proxy)):
        xs = measure(addr, a.n)
        print(f"{name:24s} n={len(xs)}  p50={pct(xs, 50):6.1f} ms  p95={pct(xs, 95):6.1f} ms  max={max(xs):6.1f} ms")
