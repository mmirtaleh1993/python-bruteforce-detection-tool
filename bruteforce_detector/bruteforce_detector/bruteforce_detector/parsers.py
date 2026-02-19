from __future__ import annotations
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Literal
from dateutil import parser as dtparser

LogType = Literal["ssh", "apache"]

@dataclass(frozen=True)
class Event:
    ts: datetime
    ip: str
    username: Optional[str]
    source: LogType
    raw: str

_SSH_RE = re.compile(
    r"""^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*?
    Failed\spassword\sfor\s(?:invalid\suser\s)?(?P<user>[\w\-.]+)\sfrom\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})
    """,
    re.VERBOSE,
)

_APACHE_RE = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>\S+)'
)

def parse_ssh_line(line: str, year: int, tz: timezone) -> Optional[Event]:
    m = _SSH_RE.search(line)
    if not m:
        return None
    ts_str = f"{m.group('mon')} {m.group('day')} {year} {m.group('time')}"
    ts = dtparser.parse(ts_str).replace(tzinfo=tz)
    return Event(ts=ts, ip=m.group("ip"), username=m.group("user"), source="ssh", raw=line)

def parse_apache_line(line: str) -> Optional[Event]:
    m = _APACHE_RE.search(line)
    if not m:
        return None
    ts = dtparser.parse(m.group("ts"))
    return Event(ts=ts, ip=m.group("ip"), username=None, source="apache", raw=line)

def parse_line(line: str, log_type: LogType, year: int, tz: timezone) -> Optional[Event]:
    if log_type == "ssh":
        return parse_ssh_line(line, year=year, tz=tz)
    if log_type == "apache":
        return parse_apache_line(line)
    return None
