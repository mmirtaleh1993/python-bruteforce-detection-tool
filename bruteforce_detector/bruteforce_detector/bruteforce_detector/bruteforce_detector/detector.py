from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Deque, List, Optional
from .parsers import Event

@dataclass
class Finding:
    ip: str
    attempts: int
    window_minutes: int
    first_seen: datetime
    last_seen: datetime
    risk: str
    usernames: List[str]

def risk_level(attempts: int, threshold: int) -> str:
    if attempts >= threshold * 2:
        return "High"
    if attempts >= threshold:
        return "Medium"
    return "Low"

class SlidingWindowDetector:
    def __init__(self, threshold: int = 5, window_minutes: int = 5):
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self.window_minutes = window_minutes
        self.events_by_ip: Dict[str, Deque[Event]] = defaultdict(deque)
        self.usernames_by_ip: Dict[str, set[str]] = defaultdict(set)

    def ingest(self, ev: Event) -> Optional[Finding]:
        q = self.events_by_ip[ev.ip]
        q.append(ev)

        if ev.username:
            self.usernames_by_ip[ev.ip].add(ev.username)

        cutoff = ev.ts - self.window
        while q and q[0].ts < cutoff:
            q.popleft()

        attempts = len(q)
        if attempts >= self.threshold:
            users = sorted(self.usernames_by_ip[ev.ip])
            return Finding(
                ip=ev.ip,
                attempts=attempts,
                window_minutes=self.window_minutes,
                first_seen=q[0].ts,
                last_seen=q[-1].ts,
                risk=risk_level(attempts, self.threshold),
                usernames=users,
            )
        return None
