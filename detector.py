from __future__ import annotations
import argparse
import os
from datetime import datetime, timezone
from typing import List

from bruteforce_detector.parsers import parse_line, LogType
from bruteforce_detector.detector import SlidingWindowDetector, Finding
from bruteforce_detector.reporting import findings_to_json, findings_to_csv
from bruteforce_detector.utils import tail_f

def read_lines(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            yield line.rstrip("\n")

def ensure_output_dir(out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)

def run_batch(log_file: str, log_type: LogType, threshold: int, window_minutes: int, out_dir: str, year: int):
    ensure_output_dir(out_dir)
    det = SlidingWindowDetector(threshold=threshold, window_minutes=window_minutes)
    findings: List[Finding] = []

    for line in read_lines(log_file):
        ev = parse_line(line, log_type=log_type, year=year, tz=timezone.utc)
        if not ev:
            continue
        f = det.ingest(ev)
        if f:
            findings.append(f)

    latest = {}
    for f in findings:
        if (f.ip not in latest) or (f.attempts > latest[f.ip].attempts):
            latest[f.ip] = f
    final = list(latest.values())
    final.sort(key=lambda x: (-x.attempts, x.ip))

    json_path = os.path.join(out_dir, "report.json")
    csv_path = os.path.join(out_dir, "report.csv")
    findings_to_json(final, json_path)
    findings_to_csv(final, csv_path)

    print(f"\n✅ Completed. Findings: {len(final)}")
    print(f"🧾 JSON: {json_path}")
    print(f"📊 CSV : {csv_path}\n")
    for f in final:
        print(f"⚠ {f.ip} | attempts={f.attempts} in {f.window_minutes}m | risk={f.risk} | users={','.join(f.usernames) or '-'}")

def run_realtime(log_file: str, log_type: LogType, threshold: int, window_minutes: int, year: int):
    det = SlidingWindowDetector(threshold=threshold, window_minutes=window_minutes)
    print("👀 Realtime mode started (Ctrl+C to stop).")
    for line in tail_f(log_file):
        ev = parse_line(line, log_type=log_type, year=year, tz=timezone.utc)
        if not ev:
            continue
        f = det.ingest(ev)
        if f:
            print(f"🚨 ALERT | {f.ip} | {f.attempts} attempts/{f.window_minutes}m | risk={f.risk} | users={','.join(f.usernames) or '-'}")

def main():
    ap = argparse.ArgumentParser(description="Brute-force detection tool (SSH/Apache) using sliding time windows.")
    ap.add_argument("--log", required=True, help="Path to log file")
    ap.add_argument("--type", required=True, choices=["ssh", "apache"], help="Log type")
    ap.add_argument("--threshold", type=int, default=5, help="Alert threshold within the time window")
    ap.add_argument("--window", type=int, default=5, help="Time window in minutes")
    ap.add_argument("--out", default="output", help="Output directory for reports (batch mode)")
    ap.add_argument("--year", type=int, default=datetime.utcnow().year, help="Year for syslog timestamps (SSH logs)")
    ap.add_argument("--realtime", action="store_true", help="Realtime detection (tail -f style)")
    args = ap.parse_args()

    if args.realtime:
        run_realtime(args.log, args.type, args.threshold, args.window, args.year)
    else:
        run_batch(args.log, args.type, args.threshold, args.window, args.out, args.year)

if __name__ == "__main__":
    main()
