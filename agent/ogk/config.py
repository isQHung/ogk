import os
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent
DATA_DIR = PKG / "data"
WEB_DIR = Path(os.getenv("OGK_WEB_DIR") or PKG.parent / "web")


def home() -> Path:
    h = os.getenv("OGK_HOME")
    if h:
        p = Path(h)
    elif sys.platform == "win32":
        p = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / "OGK"
    else:
        p = Path("./ogk_data")
    p.mkdir(parents=True, exist_ok=True)
    return p
