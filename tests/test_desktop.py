import sys
from types import SimpleNamespace

import httpx
import pytest

from ogk import desktop


def test_desktop_opens_local_app_window(monkeypatch):
    calls = {}

    class Response:
        def raise_for_status(self):
            calls["checked"] = True

    webview = SimpleNamespace(
        create_window=lambda *args, **kwargs: calls.update(window=(args, kwargs)),
        start=lambda: calls.update(started=True),
    )
    monkeypatch.setattr(desktop.httpx, "get", lambda *args, **kwargs: Response())
    monkeypatch.setitem(sys.modules, "webview", webview)

    desktop.main()

    assert calls["checked"]
    assert calls["window"][0][0] == "OpenGuard Kids – Góc của con"
    assert calls["window"][0][1] == f"{desktop.BASE}/"
    assert calls["window"][1]["min_size"] == (720, 560)
    assert calls["started"]


def test_desktop_reports_when_agent_local_api_is_offline(monkeypatch):
    def get(*args, **kwargs):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(desktop.httpx, "get", get)

    with pytest.raises(SystemExit, match="Agent chưa chạy"):
        desktop.main()
