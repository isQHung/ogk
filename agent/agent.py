"""OGK-Agent CLI: enroll | run | uninstall | tray"""
import argparse
import getpass
import hashlib
import platform
import time
import uuid

from ogk import config
from ogk.cache import Cache
from ogk.client import ServerClient


def fingerprint():
    return hashlib.sha256(f"{platform.node()}-{uuid.getnode()}".encode()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description="OpenGuard Kids agent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll")
    e.add_argument("--server", required=True)
    e.add_argument("--code", required=True)
    e.add_argument("--ca-cert", help="chứng chỉ máy chủ (ghim chứng chỉ khi dùng TLS tự ký)")
    r = sub.add_parser("run", help="chạy ở chế độ console (dev); service dùng service.py")
    r.add_argument("--dns-port", type=int, default=53)
    r.add_argument("--block-port", type=int, default=80)
    r.add_argument("--api-port", type=int, default=47800)
    r.add_argument("--upstream", default="1.1.1.1")
    r.add_argument("--interval", type=float, default=60)
    r.add_argument("--no-lock", action="store_true", help="không khóa máy thật (dev)")
    r.add_argument("--system-dns", action="store_true", help="đổi DNS hệ thống về 127.0.0.1 + chặn DNS ngoài (Windows, Admin)")
    u = sub.add_parser("uninstall")
    u.add_argument("--email", required=True)
    sub.add_parser("tray")
    a = ap.parse_args()

    if a.cmd == "enroll":
        c = ServerClient(Cache(config.home() / "agent.db"))
        j = c.enroll(a.server, a.code, fingerprint(), platform.node(), a.ca_cert)
        print(f"Đã ghép đôi. device_id={j['device_id']} (sự đồng ý của phụ huynh đã được ghi nhận)")
    elif a.cmd == "run":
        from ogk.runner import Runner
        rn = Runner(dns_port=a.dns_port, block_port=a.block_port, api_port=a.api_port,
                    upstream=(a.upstream, 53), interval=a.interval, enforce_lock=not a.no_lock,
                    system_dns=a.system_dns)
        rn.start()
        print("OpenGuard Kids đang hỗ trợ máy này. Ctrl+C để dừng.")
        try:
            while not rn.stop_evt.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            rn.stop()
    elif a.cmd == "uninstall":
        c = ServerClient(Cache(config.home() / "agent.db"))
        c.uninstall(a.email, getpass.getpass("Mật khẩu phụ huynh: "))
        print("Đã thu hồi thiết bị (có ghi nhật ký). Hãy gỡ dịch vụ: python service.py remove")
    elif a.cmd == "tray":
        from ogk.tray import main as tray_main
        tray_main()


if __name__ == "__main__":
    main()
