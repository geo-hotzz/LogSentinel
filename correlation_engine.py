#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   Automated Correlation System                               ║
║   Brute Force & Lateral Movement Detection Engine            ║
║   [ WEB-READY VERSION ]                                      ║
║                                                              ║
║   MITRE ATT&CK Coverage:                                     ║
║     T1110.001 - Brute Force: Password Guessing               ║
║     T1078     - Valid Accounts (Post-Compromise)             ║
║     T1021.004 - Remote Services: SSH (Lateral Movement)      ║
╚══════════════════════════════════════════════════════════════╝
"""

import re
import json
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

SSH_LOG = "auth.log"
CURRENT_YEAR = datetime.now().year

# Detection thresholds (tunable)
BURST_WINDOW_MINUTES          = 2     # Time window for burst detection
BURST_COUNT_THRESHOLD         = 5     # Min failures to count as a burst
SEQUENCE_MIN_FAILURES         = 3     # Min failures before a success = suspicious
SEQUENCE_TIME_WINDOW_MINUTES  = 10    # Max gap between last failure and success
LATERAL_WINDOW_MINUTES        = 30    # How long after compromise to watch for pivoting
SESSION_SHORT_THRESHOLD_SEC   = 10    # Sessions shorter than this = suspicious

# Risk score thresholds
SCORE_CRITICAL   = 20
SCORE_HIGH       = 10
SCORE_SUSPICIOUS = 5

# ──────────────────────────────────────────────
#  REGEX PATTERNS
# ──────────────────────────────────────────────

SUCCESS_PATTERN = re.compile(
    r'^(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted.*for\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)'
)

FAILED_PATTERN = re.compile(
    r'^(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)'
)

SESSION_OPEN_PATTERN = re.compile(
    r'^(\w+\s+\d+\s+\d+:\d+:\d+).*session opened for user\s+(\S+)(?:\s+by\s+(\S+))?'
)

SESSION_CLOSE_PATTERN = re.compile(
    r'^(\w+\s+\d+\s+\d+:\d+:\d+).*session closed for user\s+(\S+)'
)

NEW_CONNECTION_PATTERN = re.compile(
    r'^(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*(?:Connection from|Received disconnect from)\s+(\d+\.\d+\.\d+\.\d+)'
)

# ──────────────────────────────────────────────
#  UTILITY
# ──────────────────────────────────────────────

def parse_timestamp(ts_string):
    """
    Parse syslog timestamp to datetime.
    Year-boundary fix: if parsed date is in the future, roll back one year.
    """
    try:
        dt = datetime.strptime(
            f"{CURRENT_YEAR} {ts_string.strip()}", "%Y %b %d %H:%M:%S"
        )
        if dt > datetime.now() + timedelta(days=1):
            dt = dt.replace(year=CURRENT_YEAR - 1)
        return dt
    except ValueError:
        return None


def time_diff_minutes(t1, t2):
    """Absolute difference in minutes between two datetimes."""
    return abs((t2 - t1).total_seconds()) / 60


# ──────────────────────────────────────────────
#  PARSER
# ──────────────────────────────────────────────

def parse_ssh_log(file_path):
    """
    Single-pass log parser.
    Returns:
      events          — sorted list of SUCCESS/FAILED login events
      sessions        — list of completed sessions with duration
      new_connections — candidate lateral movement connections
    """
    events          = []
    active_sessions = {}
    sessions        = []
    new_connections = []

    with open(file_path, "r", errors="replace") as f:
        for line in f:

            if "sshd" not in line:
                continue

            m = SUCCESS_PATTERN.search(line)
            if m:
                ts, user, ip = m.group(1), m.group(2), m.group(3)
                parsed_ts = parse_timestamp(ts)
                if parsed_ts:
                    events.append({
                        "type"      : "SUCCESS",
                        "timestamp" : parsed_ts,
                        "user"      : user,
                        "ip"        : ip
                    })
                continue

            m = FAILED_PATTERN.search(line)
            if m:
                ts, user, ip = m.group(1), m.group(2), m.group(3)
                parsed_ts = parse_timestamp(ts)
                if parsed_ts:
                    events.append({
                        "type"      : "FAILED",
                        "timestamp" : parsed_ts,
                        "user"      : user,
                        "ip"        : ip
                    })
                continue

            m = SESSION_OPEN_PATTERN.search(line)
            if m:
                ts, user = m.group(1), m.group(2)
                parsed_ts = parse_timestamp(ts)
                if parsed_ts:
                    active_sessions[user] = parsed_ts
                continue

            m = SESSION_CLOSE_PATTERN.search(line)
            if m:
                ts, user = m.group(1), m.group(2)
                parsed_ts = parse_timestamp(ts)
                if parsed_ts and user in active_sessions:
                    duration_sec = (parsed_ts - active_sessions[user]).total_seconds()
                    sessions.append({
                        "user"         : user,
                        "login_time"   : active_sessions[user],
                        "logout_time"  : parsed_ts,
                        "duration_sec" : duration_sec
                    })
                    del active_sessions[user]
                continue

            m = NEW_CONNECTION_PATTERN.search(line)
            if m:
                ts, ip = m.group(1), m.group(2)
                parsed_ts = parse_timestamp(ts)
                if parsed_ts:
                    new_connections.append({
                        "timestamp" : parsed_ts,
                        "ip"        : ip
                    })

    # Include sessions that never closed
    for user, login_time in active_sessions.items():
        sessions.append({
            "user"         : user,
            "login_time"   : login_time,
            "logout_time"  : None,
            "duration_sec" : None
        })

    sorted_events = sorted(events, key=lambda x: x["timestamp"])
    return sorted_events, sessions, new_connections


# ──────────────────────────────────────────────
#  ANALYSIS ENGINE
# ──────────────────────────────────────────────

def analyze(events, sessions, new_connections):
    """
    Core correlation engine.
    Detection modules:
      1. Burst Detection       — high-frequency failures in short window
      2. Sequence Correlation  — failures followed by success (brute force confirmed)
      3. Lateral Movement      — new connections spawned after compromise
      4. Off-Hour Anomaly      — logins outside user's normal hours
      5. Session Anomaly       — suspiciously short sessions
      6. Kill Chain Assembly   — links all stages into one correlated record
    """

    ip_stats = defaultdict(lambda: {
        "success"              : 0,
        "failed"               : 0,
        "users_targeted"       : set(),
        "fail_bursts"          : 0,
        "suspicious_sequences" : [],
        "off_hour_anomaly"     : 0,
        "lateral_movement"     : 0,
        "lateral_targets"      : set(),
        "short_sessions"       : 0,
        "correlated_attacks"   : []
    })

    # Build user baseline hour profile
    user_hour_profile = defaultdict(list)
    for e in events:
        if e["type"] == "SUCCESS":
            user_hour_profile[e["user"]].append(e["timestamp"].hour)

    user_baseline = {
        user: [h for h, _ in Counter(hours).most_common(3)]
        for user, hours in user_hour_profile.items()
    }

    # Group events by IP
    ip_events = defaultdict(list)
    for e in events:
        ip_events[e["ip"]].append(e)

    for ip, ip_ev_list in ip_events.items():

        # Basic counts + off-hour detection
        for e in ip_ev_list:
            ip_stats[ip][e["type"].lower()] += 1
            ip_stats[ip]["users_targeted"].add(e["user"])

            if e["type"] == "SUCCESS":
                usual = user_baseline.get(e["user"], [])
                if usual and e["timestamp"].hour not in usual:
                    ip_stats[ip]["off_hour_anomaly"] += 1

        # Burst Detection — O(n) sliding window
        fail_times = [
            e["timestamp"] for e in ip_ev_list if e["type"] == "FAILED"
        ]
        left = 0
        burst_window_sec = BURST_WINDOW_MINUTES * 60
        for right in range(len(fail_times)):
            while (fail_times[right] - fail_times[left]).total_seconds() > burst_window_sec:
                left += 1
            if (right - left + 1) == BURST_COUNT_THRESHOLD:
                ip_stats[ip]["fail_bursts"] += 1

        # Suspicious Sequence + Lateral Movement Correlation
        fail_streak = []

        for e in ip_ev_list:
            if e["type"] == "FAILED":
                fail_streak.append(e)

            elif e["type"] == "SUCCESS":
                if len(fail_streak) >= SEQUENCE_MIN_FAILURES:
                    last_fail_time = fail_streak[-1]["timestamp"]
                    success_time   = e["timestamp"]
                    gap_min        = time_diff_minutes(last_fail_time, success_time)

                    if gap_min <= SEQUENCE_TIME_WINDOW_MINUTES:

                        # Brute Force Confirmed
                        seq_record = {
                            "failures_count"   : len(fail_streak),
                            "first_failure"    : str(fail_streak[0]["timestamp"]),
                            "last_failure"     : str(last_fail_time),
                            "success_time"     : str(success_time),
                            "compromised_user" : e["user"],
                            "time_gap_minutes" : round(gap_min, 2),
                            "ttp"              : "T1110.001 - Brute Force: Password Guessing"
                        }
                        ip_stats[ip]["suspicious_sequences"].append(seq_record)

                        # Lateral Movement Detection
                        lateral_window_end = success_time + timedelta(
                            minutes=LATERAL_WINDOW_MINUTES
                        )
                        for conn in new_connections:
                            if (conn["ip"] != ip
                                    and success_time <= conn["timestamp"] <= lateral_window_end):

                                ip_stats[ip]["lateral_movement"] += 1
                                ip_stats[ip]["lateral_targets"].add(conn["ip"])

                                # Full Kill Chain Record
                                kill_chain = {
                                    "stage_1_brute_force": {
                                        "attacker_ip" : ip,
                                        "failures"    : len(fail_streak),
                                        "start_time"  : str(fail_streak[0]["timestamp"]),
                                        "end_time"    : str(last_fail_time),
                                        "ttp"         : "T1110.001 - Password Guessing"
                                    },
                                    "stage_2_initial_access": {
                                        "compromise_time" : str(success_time),
                                        "user"            : e["user"],
                                        "ttp"             : "T1078 - Valid Accounts"
                                    },
                                    "stage_3_lateral_movement": {
                                        "pivot_time"    : str(conn["timestamp"]),
                                        "target_ip"     : conn["ip"],
                                        "delta_minutes" : round(
                                            time_diff_minutes(success_time, conn["timestamp"]), 2
                                        ),
                                        "ttp"           : "T1021.004 - SSH Lateral Movement"
                                    }
                                }
                                ip_stats[ip]["correlated_attacks"].append(kill_chain)

                fail_streak = []

    # Session Anomaly Detection
    ip_success_times = defaultdict(list)
    for e in events:
        if e["type"] == "SUCCESS":
            ip_success_times[e["user"]].append((e["ip"], e["timestamp"]))

    for session in sessions:
        if session["duration_sec"] is None:
            continue
        if session["duration_sec"] < SESSION_SHORT_THRESHOLD_SEC:
            user = session["user"]
            for ip, login_ts in ip_success_times.get(user, []):
                if abs((login_ts - session["login_time"]).total_seconds()) < 5:
                    ip_stats[ip]["short_sessions"] += 1
                    break

    return ip_stats


# ──────────────────────────────────────────────
#  RISK SCORING ENGINE
# ──────────────────────────────────────────────

def calculate_risk(data):
    """
    Weighted risk score.
    Lateral movement carries highest weight — confirms full compromise chain.
    """
    score = (
        data["failed"]                         * 1  +
        data["fail_bursts"]                    * 5  +
        len(data["suspicious_sequences"])      * 4  +
        len(data["users_targeted"])            * 2  +
        data["off_hour_anomaly"]               * 2  +
        data["short_sessions"]                 * 3  +
        data["lateral_movement"]               * 10
    )

    if score >= SCORE_CRITICAL:
        level = "CRITICAL"
    elif score >= SCORE_HIGH:
        level = "HIGH"
    elif score >= SCORE_SUSPICIOUS:
        level = "SUSPICIOUS"
    else:
        level = "NORMAL"

    return score, level


# ──────────────────────────────────────────────
#  REPORTING
# ──────────────────────────────────────────────

def generate_report(stats, json_mode=False, ip_filter=None, risk_only=False):
    """
    Build detection report.
    FIX: Always returns output dict — used by Flask web service.
    Prints to terminal if json_mode=False.
    """
    output = {}

    for ip, data in stats.items():
        if ip_filter and ip != ip_filter:
            continue

        score, level = calculate_risk(data)

        if risk_only and level == "NORMAL":
            continue

        output[ip] = {
            "ip"         : ip,
            "risk_level" : level,
            "risk_score" : score,
            "summary": {
                "total_failures"  : data["failed"],
                "total_successes" : data["success"],
                "users_count"     : len(data["users_targeted"]),
                "users_list"      : list(data["users_targeted"])
            },
            "indicators": {
                "fail_bursts"           : data["fail_bursts"],
                "brute_force_sequences" : len(data["suspicious_sequences"]),
                "off_hour_anomalies"    : data["off_hour_anomaly"],
                "short_sessions"        : data["short_sessions"],
                "lateral_movement_hits" : data["lateral_movement"],
                "lateral_targets"       : list(data["lateral_targets"])
            },
            "sequence_details" : data["suspicious_sequences"],
            "kill_chains"      : data["correlated_attacks"]
        }

    if json_mode:
        print(json.dumps(output, indent=4, default=str))
    else:
        _print_terminal_report(output)

    # FIX 1: Always return output — Flask callable
    return output


def _print_terminal_report(output):
    """
    FIX 2: Clean terminal report — ANSI color codes removed.
    Safe for web service logs and plain text environments.
    """

    print("\n" + "=" * 62)
    print("   AUTOMATED CORRELATION SYSTEM - DETECTION REPORT")
    print("   Brute Force & Lateral Movement Analyzer")
    print("=" * 62)

    if not output:
        print("\n[OK] No suspicious activity detected across all IPs.\n")
        return

    for ip, entry in output.items():
        level = entry["risk_level"]
        score = entry["risk_score"]

        print(f"\n{'─' * 62}")
        print(f"  [{level}]  IP: {ip}   |   Risk Score: {score}")
        print(f"{'─' * 62}")

        s = entry["summary"]
        print(f"  Login Statistics:")
        print(f"    Failed Attempts   : {s['total_failures']}")
        print(f"    Successful Logins : {s['total_successes']}")
        print(f"    Users Targeted    : {s['users_count']}  ->  {s['users_list']}")

        ind = entry["indicators"]
        print(f"\n  Detection Indicators:")
        print(f"    Burst Events             : {ind['fail_bursts']}")
        print(f"    Brute Force Sequences    : {ind['brute_force_sequences']}")
        print(f"    Off-Hour Anomalies       : {ind['off_hour_anomalies']}")
        print(f"    Short Sessions           : {ind['short_sessions']}")
        print(f"    Lateral Movement Hits    : {ind['lateral_movement_hits']}")

        if ind["lateral_targets"]:
            print(f"    Lateral Targets          : {ind['lateral_targets']}")

        if entry["sequence_details"]:
            print(f"\n  Brute Force Sequences:")
            for i, seq in enumerate(entry["sequence_details"], 1):
                print(f"    Sequence #{i}:")
                print(f"      Failures      : {seq['failures_count']}")
                print(f"      First Failure : {seq['first_failure']}")
                print(f"      Last Failure  : {seq['last_failure']}")
                print(f"      Success At    : {seq['success_time']}")
                print(f"      User          : {seq['compromised_user']}")
                print(f"      Time Gap      : {seq['time_gap_minutes']} min")
                print(f"      TTP           : {seq['ttp']}")

        if entry["kill_chains"]:
            print(f"\n  [!!] FULL KILL CHAIN DETECTED")
            for i, chain in enumerate(entry["kill_chains"], 1):
                print(f"\n    Kill Chain #{i}:")
                for stage, detail in chain.items():
                    label = stage.replace("_", " ").upper()
                    print(f"    [ {label} ]")
                    for k, v in detail.items():
                        print(f"      {k:<22}: {v}")

    total = len(output)
    crit  = sum(1 for e in output.values() if e["risk_level"] == "CRITICAL")
    high  = sum(1 for e in output.values() if e["risk_level"] == "HIGH")
    susp  = sum(1 for e in output.values() if e["risk_level"] == "SUSPICIOUS")

    print(f"\n{'=' * 62}")
    print(f"  SUMMARY  |  IPs: {total}  Critical: {crit}  High: {high}  Suspicious: {susp}")
    print(f"{'=' * 62}\n")


# ──────────────────────────────────────────────
#  FIX 3: WEB-CALLABLE FUNCTION  ← NEW
#  Flask imports and calls this directly.
#  No printing — returns clean dict only.
# ──────────────────────────────────────────────

def run_analysis(file_path):
    """
    Single entry point for Flask / web service integration.

    Usage in Flask:
        from correlation_engine import run_analysis
        result = run_analysis("/tmp/uploaded_auth.log")
        return jsonify(result)

    Args:
        file_path (str): Path to the uploaded auth.log file

    Returns:
        dict: Full report with risk scores and kill chains per IP
    """
    events, sessions, new_connections = parse_ssh_log(file_path)
    stats  = analyze(events, sessions, new_connections)
    report = generate_report(stats, json_mode=False)
    return report


# ──────────────────────────────────────────────
#  MAIN — CLI still works exactly as before
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Automated Correlation System - Brute Force & Lateral Movement Detection",
        epilog="MITRE ATT&CK: T1110 | T1021.004 | T1078"
    )
    parser.add_argument(
        "--file", default=SSH_LOG,
        help="Path to auth.log (default: auth.log)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output report in JSON format"
    )
    parser.add_argument(
        "--ip",
        help="Filter report for a specific source IP"
    )
    parser.add_argument(
        "--risk-only", action="store_true",
        help="Show only SUSPICIOUS / HIGH / CRITICAL IPs"
    )

    args = parser.parse_args()

    print(f"\n[*] Loading log file    : {args.file}")
    events, sessions, new_connections = parse_ssh_log(args.file)

    print(f"[*] Events parsed       : {len(events)}")
    print(f"[*] Sessions tracked    : {len(sessions)}")
    print(f"[*] Lateral candidates  : {len(new_connections)}\n")

    stats = analyze(events, sessions, new_connections)

    print(f"[*] Unique IPs analyzed : {len(stats)}")

    generate_report(
        stats,
        json_mode = args.json,
        ip_filter = args.ip,
        risk_only = args.risk_only
    )


if __name__ == "__main__":
    main()
