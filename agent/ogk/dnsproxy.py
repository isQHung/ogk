"""F2: DNS proxy cục bộ – chặn theo tên miền/nhóm, SafeSearch, đối phó DoH."""
import csv
import socket
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dnslib import A, CNAME, QTYPE, RCODE, RR, DNSRecord
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from .config import DATA_DIR
from .domains import matches

CAT_VN = {"education": "Giáo dục", "entertainment": "Giải trí", "social": "Mạng xã hội",
          "games": "Trò chơi", "inappropriate": "Không phù hợp lứa tuổi"}

SAFE_MAP = {  # SafeSearch cưỡng chế bằng DNS (danh sách Google chưa đầy đủ mọi ccTLD)
    "google.com": "forcesafesearch.google.com", "www.google.com": "forcesafesearch.google.com",
    "google.com.vn": "forcesafesearch.google.com", "www.google.com.vn": "forcesafesearch.google.com",
    "www.google.co.uk": "forcesafesearch.google.com", "www.bing.com": "strict.bing.com",
    "duckduckgo.com": "safe.duckduckgo.com", "www.duckduckgo.com": "safe.duckduckgo.com",
    "www.youtube.com": "restrict.youtube.com", "m.youtube.com": "restrict.youtube.com",
    "youtubei.googleapis.com": "restrict.youtube.com", "www.youtube-nocookie.com": "restrict.youtube.com",
}


def load_categories(path=DATA_DIR / "categories.csv") -> dict:
    with open(path, encoding="utf-8") as f:
        return {r["domain"].strip().lower(): r["category"].strip() for r in csv.DictReader(f)}


def load_list(path) -> list:
    with open(path, encoding="utf-8") as f:
        return [l.strip().lower() for l in f if l.strip() and not l.startswith("#")]


def lookup_category(cats: dict, host: str):
    parts = host.split(".")
    for i in range(len(parts) - 1):
        c = cats.get(".".join(parts[i:]))
        if c:
            return c
    return None


@dataclass
class Decision:
    action: str = "allow"   # allow | block | nx
    reason: str = ""
    who: str = ""
    category: str | None = None


def decide_domain(policy: dict, cats: dict, exempt: list, doh: list, host: str) -> Decision:
    host = host.lower().rstrip(".")
    who = policy.get("set_by", "")
    if any(matches(host, d) for d in exempt):
        return Decision("allow", "Danh sách miễn chặn vĩnh viễn (NT6)")
    if host == "use-application-dns.net" or any(matches(host, d) for d in doh):
        return Decision("nx", "Điểm cuối DNS-over-HTTPS bị chặn để bộ lọc hoạt động", who)
    best = None
    for r in policy.get("domain_rules", []):
        d = r["domain"].lower().strip(".")
        if matches(host, d) and (best is None or len(d) > len(best[0])):
            best = (d, r)
    if best:
        d, r = best
        if r["action"] == "allow":
            return Decision("allow", f"Phụ huynh cho phép {d}", r.get("set_by", who))
        return Decision("block", f"Phụ huynh đã chặn {d}", r.get("set_by", who))
    cat = lookup_category(cats, host)
    if cat in policy.get("blocked_categories", []):
        return Decision("block", f"Nhóm “{CAT_VN.get(cat, cat)}” đang bị chặn", who, cat)
    if cat is None and policy.get("block_uncategorized"):
        return Decision("block", "Trang chưa được phân loại", who)
    return Decision("allow", "", who, cat)


class FilterResolver(BaseResolver):
    def __init__(self, get_policy, cats, exempt, doh, upstream=("1.1.1.1", 53),
                 on_query=lambda n: None, on_block=lambda n, d: None, block_ip="127.0.0.1", timeout=3):
        self.get_policy, self.cats, self.exempt, self.doh = get_policy, cats, exempt, doh
        self.upstream, self.on_query, self.on_block = upstream, on_query, on_block
        self.block_ip, self.timeout = block_ip, timeout

    def decide(self, name):
        return decide_domain(self.get_policy() or {}, self.cats, self.exempt, self.doh, name)

    def _forward(self, rec: DNSRecord) -> DNSRecord:
        return DNSRecord.parse(rec.send(self.upstream[0], self.upstream[1], timeout=self.timeout))

    def resolve(self, request, handler):
        reply, q = request.reply(), request.q
        name, qt = str(q.qname).rstrip(".").lower(), QTYPE[q.qtype]
        pol = self.get_policy() or {}
        d = self.decide(name)
        if d.action == "nx":
            reply.header.rcode = RCODE.NXDOMAIN
            self.on_block(name, d)
            return reply
        if d.action == "block":
            self.on_block(name, d)
            if qt == "A":  # trỏ về trang giải thích cục bộ; AAAA để trống tránh vòng qua IPv6
                reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(self.block_ip), ttl=30))
            return reply
        try:
            target = SAFE_MAP.get(name) if pol.get("safesearch", True) else None
            if target:
                if qt == "A":
                    up = self._forward(DNSRecord.question(target, "A"))
                    reply.add_answer(RR(q.qname, QTYPE.CNAME, rdata=CNAME(target), ttl=60))
                    for rr in up.rr:
                        if rr.rtype == QTYPE.A:
                            reply.add_answer(RR(target, QTYPE.A, rdata=rr.rdata, ttl=60))
                return reply
            self.on_query(name)
            return self._forward(request)
        except (socket.timeout, OSError):
            reply.header.rcode = RCODE.SERVFAIL
            return reply


def start_dns(resolver, bind="127.0.0.1", port=53):
    lg = DNSLogger(log="", prefix=False)
    servers = [DNSServer(resolver, port=port, address=bind, logger=lg, tcp=False),
               DNSServer(resolver, port=port, address=bind, logger=lg, tcp=True)]
    for s in servers:
        s.start_thread()
    return servers


# ---- trang giải thích khi bị chặn (NT4: không im lặng, không giả vờ lỗi mạng) ----
def start_block_page(decide, port=80, bind="127.0.0.1"):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            host = (self.headers.get("Host") or "").split(":")[0]
            d = decide(host)
            who = d.who or "phụ huynh"
            body = (f"<html><meta charset='utf-8'><body style='font-family:sans-serif;max-width:560px;margin:3rem auto'>"
                    f"<h1>Trang này đang bị chặn</h1><p><b>Lý do:</b> {d.reason or 'Theo quy tắc hiện hành'}</p>"
                    f"<p><b>Luật do:</b> {who} đặt ra.</p>"
                    f"<p>Nếu con nghĩ đây là nhầm lẫn, hãy bấm “Con nghĩ trang này bị chặn nhầm” ở biểu tượng "
                    f"OpenGuard Kids trên thanh tác vụ.</p></body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer((bind, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
