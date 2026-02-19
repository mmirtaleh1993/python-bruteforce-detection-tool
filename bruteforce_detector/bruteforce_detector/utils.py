from __future__ import annotations
import os
import time
from typing import Iterator

def tail_f(path: str, sleep: float = 0.5) -> Iterator[str]:
    """Yield new lines as they are appended to a file (tail -f)."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                yield line.rstrip("\n")
            else:
                time.sleep(sleep)
