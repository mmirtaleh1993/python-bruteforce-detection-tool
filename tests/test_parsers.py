from datetime import timezone
from bruteforce_detector.parsers import parse_line

def test_parse_ssh_line():
    line = "Feb 19 10:01:01 server sshd[111]: Failed password for invalid user admin from 192.168.1.10 port 51422 ssh2"
    ev = parse_line(line, log_type="ssh", year=2026, tz=timezone.utc)
    assert ev is not None
    assert ev.ip == "192.168.1.10"
    assert ev.username == "admin"
