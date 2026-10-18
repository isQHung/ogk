"""Phần phụ thuộc Windows. Trên hệ điều hành khác: no-op để chạy/kiểm thử được."""
import ipaddress
import subprocess
import sys

IS_WIN = sys.platform == "win32"


def idle_seconds() -> float:
    if not IS_WIN:
        return 0.0
    import ctypes

    class LII(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
    lii = LII(ctypes.sizeof(LII), 0)
    ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii))
    return (ctypes.windll.kernel32.GetTickCount() - lii.dwTime) / 1000.0


def lock_session():
    """Service (session 0) không gọi LockWorkStation được: ngắt kết nối phiên console -> về màn hình đăng nhập.
    Không đụng tới cuộc gọi khẩn cấp của hệ điều hành (NT6)."""
    if not IS_WIN:
        return
    try:
        import win32ts
        win32ts.WTSDisconnectSession(win32ts.WTS_CURRENT_SERVER_HANDLE, win32ts.WTSGetActiveConsoleSessionId(), False)
    except Exception:
        import ctypes
        ctypes.windll.user32.LockWorkStation()


def visible_pids():
    """PID có cửa sổ hiển thị (để chỉ theo dõi 'ứng dụng người dùng'). None = không xác định."""
    if not IS_WIN:
        return None
    import win32gui
    import win32process
    pids = set()

    def cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd):
            pids.add(win32process.GetWindowThreadProcessId(hwnd)[1])
    win32gui.EnumWindows(cb, None)
    return pids


def _ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True)


def set_system_dns_to_local():
    if IS_WIN:
        _ps("Get-NetAdapter | Where-Object Status -eq 'Up' | Set-DnsClientServerAddress -ServerAddresses 127.0.0.1")


def restore_system_dns():
    if IS_WIN:
        _ps("Get-NetAdapter | Set-DnsClientServerAddress -ResetServerAddresses")


def flush_dns():
    if IS_WIN:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True)

def _complement(ip: str):
    n = int(ipaddress.IPv4Address(ip))
    lo = f"0.0.0.0-{ipaddress.IPv4Address(n - 1)}" if n > 0 else None
    hi = f"{ipaddress.IPv4Address(n + 1)}-255.255.255.255" if n < 2**32 - 1 else None
    return ",".join(x for x in (lo, hi) if x)


def block_external_dns(upstream_ip: str):
    """Chặn DNS (53) và DoT (853) ra ngoài, trừ máy chủ upstream của agent. Giới hạn: trẻ vẫn tự gõ được upstream."""
    if not IS_WIN:
        return
    rng = _complement(upstream_ip)
    for proto in ("UDP", "TCP"):
        for port in ("53", "853"):
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", f"name=OGK-DNS-{proto}-{port}",
                            "dir=out", "action=block", f"protocol={proto}", f"remoteport={port}",
                            f"remoteip={rng}"], capture_output=True)


def unblock_external_dns():
    if IS_WIN:
        for proto in ("UDP", "TCP"):
            for port in ("53", "853"):
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=OGK-DNS-{proto}-{port}"],
                               capture_output=True)


def protect_home(path):
    """Thư mục cấu hình: chỉ SYSTEM/Administrators được ghi; Users chỉ đọc."""
    if IS_WIN:
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)F",
                        "Administrators:(OI)(CI)F", "Users:(OI)(CI)RX"], capture_output=True)
