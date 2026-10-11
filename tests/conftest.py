import os
import sys
import tempfile
from pathlib import Path

_tmp = tempfile.mkdtemp()
os.environ["OGK_DB"] = f"sqlite:///{_tmp}/test.db"
os.environ["OGK_KEY_DIR"] = f"{_tmp}/keys"
os.environ["OGK_RATE_MAX"] = "100000"
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "agent"))

import socket

import pytest


@pytest.fixture()
def free_ports():
    def get(n=1):
        socks = [socket.socket() for _ in range(n)]
        for s in socks:
            s.bind(("127.0.0.1", 0))
        ports = [s.getsockname()[1] for s in socks]
        for s in socks:
            s.close()
        return ports
    return get
