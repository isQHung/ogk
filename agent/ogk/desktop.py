"""Desktop window for the child's local transparency UI."""
import httpx

from .tray import BASE


def main():
    try:
        response = httpx.get(f"{BASE}/", timeout=2)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise SystemExit("Agent chưa chạy. Trước tiên chạy: python agent.py run") from exc

    try:
        import webview
    except ImportError as exc:
        raise SystemExit("Thiếu pywebview. Cài bằng: python -m pip install -r requirements.txt") from exc

    webview.create_window(
        "OpenGuard Kids – Góc của con",
        BASE + "/",
        width=1080,
        height=800,
        min_size=(720, 560),
        text_select=True,
    )
    webview.start()
