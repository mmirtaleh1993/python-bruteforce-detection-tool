from __future__ import annotations
import csv
import json
from dataclasses import asdict
from typing import List
from .detector import Finding

def findings_to_json(findings: List[Finding], path: str) -> None:
    payload = []
    for f in findings:
        d = asdict(f)
        d["first_seen"] = f.first_seen.isoformat()
        d["last_seen"] = f.last_seen.isoformat()
        payload.append(d)
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2)

def findings_to_csv(findings: List[Finding], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow(["ip", "attempts", "window_minutes", "risk", "first_seen", "last_seen", "usernames"])
        for f in findings:
            w.writerow([f.ip, f.attempts, f.window_minutes, f.risk,
                        f.first_seen.isoformat(), f.last_seen.isoformat(),
                        ";".join(f.usernames)])
