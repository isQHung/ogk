"""Tray UI (chạy trong phiên người dùng): biểu tượng luôn hiển thị (NT1), giờ còn lại, xin thêm giờ (NT3)."""
import threading
import time
import subprocess
import sys
from pathlib import Path

import httpx

from . import config

BASE = "http://127.0.0.1:47800"


def main():
    import pystray
    import tkinter as tk
    from tkinter import messagebox, simpledialog
    from PIL import Image, ImageDraw

    token = (config.home() / "local_token").read_text().strip()
    hdr = {"X-OGK-Token": token}

    def img():
        im = Image.new("RGB", (64, 64), "white")
        ImageDraw.Draw(im).ellipse((6, 6, 58, 58), fill="#2b8a3e")
        return im

    def dialog(fn):
        def run():
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)
            fn(root)
            root.destroy()
        threading.Thread(target=run, daemon=True).start()

    def send(payload):
        try:
            r = httpx.post(f"{BASE}/help", headers=hdr, json=payload, timeout=10)
            r.raise_for_status()
            return True
        except httpx.HTTPError:
            return False

    def more_time(icon=None, item=None):
        def f(root):
            m = simpledialog.askinteger("Xin thêm giờ", "Con muốn xin thêm bao nhiêu phút? (1–120)", parent=root,
                                        minvalue=1, maxvalue=120)
            if m:
                note = simpledialog.askstring("Xin thêm giờ", "Lý do (không bắt buộc):", parent=root) or ""
                ok = send({"kind": "more_time", "minutes": m, "note": note})
                messagebox.showinfo("OpenGuard Kids", "Đã gửi cho phụ huynh." if ok else "Chưa gửi được, hãy thử lại.", parent=root)
        dialog(f)

    def wrong_block(icon=None, item=None):
        def f(root):
            d = simpledialog.askstring("Chặn nhầm?", "Trang web bị chặn là gì? (vd: example.com)", parent=root)
            if d:
                ok = send({"kind": "wrong_block", "subject": d.strip().lower()})
                messagebox.showinfo("OpenGuard Kids", "Đã gửi cho phụ huynh." if ok else "Chưa gửi được.", parent=root)
        dialog(f)

    def about(icon=None, item=None):
        dialog(lambda root: messagebox.showinfo(
            "OpenGuard Kids", "Công cụ do phụ huynh cài để đồng hành cùng con.\nChỉ ghi: tên ứng dụng, tên miền, thời lượng.\n"
            "Không ghi: nội dung tin nhắn, phím gõ, ảnh màn hình.\nCon xem được mọi thứ ở mục “Hôm nay em đã dùng gì”.", parent=root))

    def open_ui(icon=None, item=None):
        script = Path(__file__).resolve().parents[1] / "agent.py"
        subprocess.Popen([sys.executable, str(script), "ui"], close_fds=True)

    menu = pystray.Menu(pystray.MenuItem("Mở ứng dụng OpenGuard Kids", open_ui),
                        pystray.MenuItem("Xin thêm giờ", more_time),
                        pystray.MenuItem("Con nghĩ trang này bị chặn nhầm", wrong_block),
                        pystray.MenuItem("Về OpenGuard Kids", about))
    icon = pystray.Icon("ogk", img(), "OpenGuard Kids", menu)

    def poll():
        while True:
            try:
                s = httpx.get(f"{BASE}/state", headers=hdr, timeout=5).json()
                rem = s.get("remaining_sec")
                icon.title = "OpenGuard Kids" + (f" – còn {rem // 60} phút" if rem is not None else "")
                for n in s.get("notes", []):
                    icon.notify(f"{n['text']}" + (f"\nLuật do: {n['who']}" if n["who"] else ""), n["title"])
                    if n["kind"] in ("app", "domain"):  # cửa sổ giải thích, không im lặng (NT4)
                        dialog(lambda root, n=n: messagebox.showinfo(
                            n["title"], f"{n['text']}\nLuật do: {n['who'] or 'phụ huynh'} đặt ra.", parent=root))
            except Exception:
                icon.title = "OpenGuard Kids – chưa kết nối agent"
            time.sleep(2)

    threading.Thread(target=poll, daemon=True).start()
    icon.run()
