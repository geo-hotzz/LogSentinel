"""
╔══════════════════════════════════════════════════════════════╗
║   LogSentinel — Windows Event Log Parser                     ║
║                                                              ║
║   Supported Event IDs:                                       ║
║     4624 — Successful Logon                                  ║
║     4625 — Failed Logon                                      ║
║     4648 — Logon with Explicit Credentials (Lateral Move)    ║
║     4672 — Special Privileges Assigned (Privilege Escalation)║
║                                                              ║
║   Input Formats:                                             ║
║     .evtx  — Windows Event Log binary                        ║
║     .xml   — Exported Event Log XML                          ║
║     .txt   — PowerShell Get-WinEvent text export             ║
║     .csv   — PowerShell CSV export                           ║
║                                                              ║
║   MITRE ATT&CK Coverage:                                     ║
║     T1110.001 — Brute Force: Password Guessing               ║
║     T1078     — Valid Accounts                               ║
║     T1021.001 — Remote Desktop Protocol                      ║
║     T1021.002 — SMB/Windows Admin Shares                     ║
║     T1078.002 — Domain Accounts                              ║
╚══════════════════════════════════════════════════════════════╝
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

CURRENT_YEAR = datetime.now().year

# Detection thresholds
WIN_BURST_WINDOW_MINUTES         = 2
WIN_BURST_COUNT_THRESHOLD        = 5
WIN_SEQUENCE_MIN_FAILURES        = 3
WIN_SEQUENCE_TIME_WINDOW_MINUTES = 10
WIN_LATERAL_WINDOW_MINUTES       = 30
WIN_SESSION_SHORT_THRESHOLD_SEC  = 10

# Risk score thresholds
WIN_SCORE_CRITICAL   = 20
WIN_SCORE_HIGH       = 10
WIN_SCORE_SUSPICIOUS = 5

# Windows Event ID definitions
EVENT_IDS = {
    4624: "SUCCESS",           # Successful logon
    4625: "FAILED",            # Failed logon
    4648: "LATERAL",           # Logon with explicit credentials
    4672: "PRIVILEGE",         # Special privileges assigned
}

# Logon type descriptions
LOGON_TYPES = {
    "2" : "Interactive",
    "3" : "Network",
    "4" : "Batch",
    "5" : "Service",
    "7" : "Unlock",
    "8" : "NetworkCleartext",
    "9" : "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}

# ──────────────────────────────────────────────
#  PARSERS
# ──────────────────────────────────────────────

def parse_windows_log(file_path):
    """
    Auto-detect format and parse Windows Event Log.
    Returns: (events, log_type)
    """
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""

    if ext == "evtx":
        return _parse_evtx(file_path), "evtx"
    elif ext == "xml":
        return _parse_xml(file_path), "xml"
    elif ext == "csv":
        return _parse_csv(file_path), "csv"
    else:
        # Try XML first, then text
        try:
            return _parse_xml(file_path), "xml"
        except Exception:
            return _parse_text(file_path), "text"


def _parse_evtx(file_path):
    """Parse binary .evtx Windows Event Log file."""
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views
    except ImportError:
        raise ImportError(
            "python-evtx not installed. Run: pip install python-evtx"
        )

    events = []
    with evtx.Evtx(file_path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                event   = _parse_event_xml(xml_str)
                if event:
                    events.append(event)
            except Exception:
                continue

    return sorted(events, key=lambda x: x["timestamp"])


def _parse_xml(file_path):
    """Parse XML-exported Windows Event Log."""
    events = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Handle both wrapped <Events> and bare <Event> formats
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

        event_elements = (
            root.findall(".//e:Event", ns) or
            root.findall(".//Event") or
            ([root] if root.tag in ("Event", "{http://schemas.microsoft.com/win/2004/08/events/event}Event") else [])
        )

        for elem in event_elements:
            try:
                xml_str = ET.tostring(elem, encoding="unicode")
                event   = _parse_event_xml(xml_str)
                if event:
                    events.append(event)
            except Exception:
                continue

    except ET.ParseError:
        # Try parsing as multiple XML documents
        with open(file_path, "r", errors="replace") as f:
            content = f.read()
        for match in re.finditer(r"<Event[^>]*>.*?</Event>", content, re.DOTALL):
            try:
                event = _parse_event_xml(match.group())
                if event:
                    events.append(event)
            except Exception:
                continue

    return sorted(events, key=lambda x: x["timestamp"])


def _parse_event_xml(xml_str):
    """Parse a single Windows Event XML element."""
    # Namespace handling
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    xml_str = xml_str.strip()

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    def find(path):
        result = root.find(path, ns)
        if result is None:
            # Try without namespace
            path_no_ns = re.sub(r"e:", "", path)
            result = root.find(path_no_ns)
        return result

    def findall(path):
        result = root.findall(path, ns)
        if not result:
            path_no_ns = re.sub(r"e:", "", path)
            result = root.findall(path_no_ns)
        return result

    # Get Event ID
    event_id_elem = find(".//e:EventID") or find(".//EventID")
    if event_id_elem is None:
        return None

    try:
        event_id = int(event_id_elem.text.strip())
    except (ValueError, AttributeError):
        return None

    if event_id not in EVENT_IDS:
        return None

    # Get timestamp
    system_time = None
    time_created = find(".//e:TimeCreated") or find(".//TimeCreated")
    if time_created is not None:
        st = time_created.get("SystemTime", "")
        if st:
            system_time = _parse_win_timestamp(st)

    if system_time is None:
        system_time = datetime.now()

    # Extract EventData fields
    data_fields = {}
    for data in findall(".//e:Data") + findall(".//Data"):
        name  = data.get("Name", "")
        value = (data.text or "").strip()
        if name:
            data_fields[name] = value

    # Build normalized event
    event_type   = EVENT_IDS[event_id]
    ip           = (data_fields.get("IpAddress") or
                    data_fields.get("SourceAddress") or
                    data_fields.get("WorkstationName") or "Unknown")
    user         = (data_fields.get("TargetUserName") or
                    data_fields.get("SubjectUserName") or "Unknown")
    domain       = data_fields.get("TargetDomainName", "")
    logon_type   = data_fields.get("LogonType", "")
    logon_desc   = LOGON_TYPES.get(logon_type, logon_type)
    failure_reason = data_fields.get("FailureReason", "")
    sub_status   = data_fields.get("SubStatus", "")

    # Normalize IP — skip localhost/machine events for FAILED
    if ip in ("-", "::1", "127.0.0.1", "LOCAL") and event_type == "FAILED":
        ip = "LOCAL"

    return {
        "type"          : event_type,
        "event_id"      : event_id,
        "timestamp"     : system_time,
        "user"          : user,
        "domain"        : domain,
        "ip"            : ip,
        "logon_type"    : logon_type,
        "logon_desc"    : logon_desc,
        "failure_reason": failure_reason,
        "sub_status"    : sub_status,
        "source"        : "windows"
    }


def _parse_csv(file_path):
    """Parse PowerShell CSV export of Windows Event Log."""
    import csv
    events = []

    with open(file_path, "r", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                event_id = int(row.get("Id", row.get("EventID", 0)))
                if event_id not in EVENT_IDS:
                    continue

                ts_str = row.get("TimeCreated", row.get("Time", ""))
                ts     = _parse_win_timestamp(ts_str) or datetime.now()

                message = row.get("Message", "")
                ip      = _extract_from_message(message, "Source Network Address") or "Unknown"
                user    = _extract_from_message(message, "Account Name") or "Unknown"

                events.append({
                    "type"          : EVENT_IDS[event_id],
                    "event_id"      : event_id,
                    "timestamp"     : ts,
                    "user"          : user,
                    "domain"        : "",
                    "ip"            : ip,
                    "logon_type"    : _extract_from_message(message, "Logon Type"),
                    "logon_desc"    : "",
                    "failure_reason": _extract_from_message(message, "Failure Reason"),
                    "sub_status"    : "",
                    "source"        : "windows"
                })
            except Exception:
                continue

    return sorted(events, key=lambda x: x["timestamp"])


def _parse_text(file_path):
    """
    Parse plain text Windows Event Log export.
    Handles Get-WinEvent | Format-List output.
    """
    events   = []
    event_id = None
    ts       = None
    message  = []

    with open(file_path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip()

            id_match = re.search(r"Id\s*:\s*(\d+)", line)
            if id_match:
                if event_id and ts:
                    ev = _build_text_event(event_id, ts, "\n".join(message))
                    if ev:
                        events.append(ev)
                event_id = int(id_match.group(1))
                ts       = None
                message  = []
                continue

            ts_match = re.search(r"TimeCreated\s*:\s*(.+)", line)
            if ts_match:
                ts = _parse_win_timestamp(ts_match.group(1).strip())
                continue

            message.append(line)

    if event_id and ts:
        ev = _build_text_event(event_id, ts, "\n".join(message))
        if ev:
            events.append(ev)

    return sorted(events, key=lambda x: x["timestamp"])


def _build_text_event(event_id, ts, message):
    if event_id not in EVENT_IDS:
        return None
    ip   = _extract_from_message(message, "Source Network Address") or "Unknown"
    user = _extract_from_message(message, "Account Name") or "Unknown"
    return {
        "type"          : EVENT_IDS[event_id],
        "event_id"      : event_id,
        "timestamp"     : ts,
        "user"          : user,
        "domain"        : _extract_from_message(message, "Account Domain") or "",
        "ip"            : ip,
        "logon_type"    : _extract_from_message(message, "Logon Type") or "",
        "logon_desc"    : "",
        "failure_reason": _extract_from_message(message, "Failure Reason") or "",
        "sub_status"    : _extract_from_message(message, "Sub Status") or "",
        "source"        : "windows"
    }


# ──────────────────────────────────────────────
#  UTILITIES
# ──────────────────────────────────────────────

def _parse_win_timestamp(ts_string):
    """Parse various Windows timestamp formats."""
    if not ts_string:
        return None
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ]
    ts_string = ts_string.strip().rstrip("Z")
    for fmt in formats:
        try:
            return datetime.strptime(ts_string[:len(fmt)], fmt)
        except ValueError:
            continue
    return None


def _extract_from_message(message, field):
    """Extract field value from Windows Event message text."""
    pattern = rf"{re.escape(field)}\s*[:\t]\s*(.+)"
    match   = re.search(pattern, message, re.IGNORECASE)
    if match:
        val = match.group(1).strip()
        return val if val not in ("-", "") else None
    return None


def time_diff_minutes(t1, t2):
    return abs((t2 - t1).total_seconds()) / 60


# ──────────────────────────────────────────────
#  ANALYSIS ENGINE
# ──────────────────────────────────────────────

def analyze_windows(events):
    """
    Windows Event Log correlation engine.
    Mirrors SSH correlation logic with Windows-specific TTPs.
    """
    ip_stats = defaultdict(lambda: {
        "success"              : 0,
        "failed"               : 0,
        "lateral"              : 0,
        "privilege"            : 0,
        "users_targeted"       : set(),
        "fail_bursts"          : 0,
        "suspicious_sequences" : [],
        "off_hour_anomaly"     : 0,
        "rdp_attempts"         : 0,
        "correlated_attacks"   : [],
        "logon_types"          : set(),
    })

    # Build user hour baseline
    user_hour_profile = defaultdict(list)
    for e in events:
        if e["type"] == "SUCCESS":
            user_hour_profile[e["user"]].append(e["timestamp"].hour)

    user_baseline = {
        user: [h for h, _ in Counter(hours).most_common(3)]
        for user, hours in user_hour_profile.items()
    }

    # Group by IP
    ip_events = defaultdict(list)
    for e in events:
        ip_events[e["ip"]].append(e)

    lateral_events = [e for e in events if e["type"] == "LATERAL"]

    for ip, ip_ev_list in ip_events.items():

        # Basic counts
        for e in ip_ev_list:
            t = e["type"]
            if t == "SUCCESS":
                ip_stats[ip]["success"] += 1
            elif t == "FAILED":
                ip_stats[ip]["failed"] += 1
            elif t == "LATERAL":
                ip_stats[ip]["lateral"] += 1
            elif t == "PRIVILEGE":
                ip_stats[ip]["privilege"] += 1

            ip_stats[ip]["users_targeted"].add(e["user"])

            if e.get("logon_desc"):
                ip_stats[ip]["logon_types"].add(e["logon_desc"])

            # RDP detection (Logon Type 10)
            if e.get("logon_type") == "10":
                ip_stats[ip]["rdp_attempts"] += 1

            # Off-hour anomaly
            if t == "SUCCESS":
                usual = user_baseline.get(e["user"], [])
                if usual and e["timestamp"].hour not in usual:
                    ip_stats[ip]["off_hour_anomaly"] += 1

        # Burst detection (O(n) sliding window)
        fail_times = [
            e["timestamp"] for e in ip_ev_list if e["type"] == "FAILED"
        ]
        left = 0
        burst_sec = WIN_BURST_WINDOW_MINUTES * 60
        for right in range(len(fail_times)):
            while (fail_times[right] - fail_times[left]).total_seconds() > burst_sec:
                left += 1
            if (right - left + 1) == WIN_BURST_COUNT_THRESHOLD:
                ip_stats[ip]["fail_bursts"] += 1

        # Sequence correlation + kill chain
        fail_streak = []
        for e in ip_ev_list:
            if e["type"] == "FAILED":
                fail_streak.append(e)
            elif e["type"] == "SUCCESS":
                if len(fail_streak) >= WIN_SEQUENCE_MIN_FAILURES:
                    last_fail = fail_streak[-1]["timestamp"]
                    gap_min   = time_diff_minutes(last_fail, e["timestamp"])

                    if gap_min <= WIN_SEQUENCE_TIME_WINDOW_MINUTES:

                        seq_record = {
                            "failures_count"   : len(fail_streak),
                            "first_failure"    : str(fail_streak[0]["timestamp"]),
                            "last_failure"     : str(last_fail),
                            "success_time"     : str(e["timestamp"]),
                            "compromised_user" : e["user"],
                            "domain"           : e.get("domain", ""),
                            "logon_type"       : e.get("logon_desc", ""),
                            "time_gap_minutes" : round(gap_min, 2),
                            "ttp"              : "T1110.001 - Brute Force: Password Guessing"
                        }
                        ip_stats[ip]["suspicious_sequences"].append(seq_record)

                        # Check for lateral movement within window
                        lateral_window_end = e["timestamp"] + timedelta(
                            minutes=WIN_LATERAL_WINDOW_MINUTES
                        )
                        for lat in lateral_events:
                            if (lat["ip"] != ip and
                                    e["timestamp"] <= lat["timestamp"] <= lateral_window_end):

                                logon_desc = lat.get("logon_desc", "")
                                ttp = ("T1021.001 - Remote Desktop Protocol"
                                       if "RDP" in logon_desc or lat.get("logon_type") == "10"
                                       else "T1021.002 - SMB/Windows Admin Shares")

                                kill_chain = {
                                    "stage_1_brute_force": {
                                        "attacker_ip" : ip,
                                        "failures"    : len(fail_streak),
                                        "start_time"  : str(fail_streak[0]["timestamp"]),
                                        "end_time"    : str(last_fail),
                                        "ttp"         : "T1110.001 - Password Guessing"
                                    },
                                    "stage_2_initial_access": {
                                        "compromise_time" : str(e["timestamp"]),
                                        "user"            : e["user"],
                                        "domain"          : e.get("domain", ""),
                                        "logon_type"      : e.get("logon_desc", ""),
                                        "ttp"             : "T1078 - Valid Accounts"
                                    },
                                    "stage_3_lateral_movement": {
                                        "pivot_time"    : str(lat["timestamp"]),
                                        "target_ip"     : lat["ip"],
                                        "target_user"   : lat.get("user", ""),
                                        "delta_minutes" : round(
                                            time_diff_minutes(e["timestamp"], lat["timestamp"]), 2
                                        ),
                                        "ttp"           : ttp
                                    }
                                }
                                ip_stats[ip]["correlated_attacks"].append(kill_chain)

                fail_streak = []

    return ip_stats


# ──────────────────────────────────────────────
#  RISK SCORING
# ──────────────────────────────────────────────

def calculate_windows_risk(data):
    """
    Weighted risk score for Windows events.
    Privilege escalation and RDP carry extra weight.
    """
    score = (
        data["failed"]                         * 1  +
        data["fail_bursts"]                    * 5  +
        len(data["suspicious_sequences"])      * 4  +
        len(data["users_targeted"])            * 2  +
        data["off_hour_anomaly"]               * 2  +
        data["rdp_attempts"]                   * 3  +
        data["privilege"]                      * 5  +
        data["lateral"]                        * 8  +
        len(data["correlated_attacks"])        * 10
    )

    if score >= WIN_SCORE_CRITICAL:
        level = "CRITICAL"
    elif score >= WIN_SCORE_HIGH:
        level = "HIGH"
    elif score >= WIN_SCORE_SUSPICIOUS:
        level = "SUSPICIOUS"
    else:
        level = "NORMAL"

    return score, level


# ──────────────────────────────────────────────
#  REPORT BUILDER
# ──────────────────────────────────────────────

def build_windows_report(stats):
    """Build structured report from Windows analysis."""
    output = {}

    for ip, data in stats.items():
        score, level = calculate_windows_risk(data)

        output[ip] = {
            "ip"         : ip,
            "risk_level" : level,
            "risk_score" : score,
            "source"     : "windows",
            "summary": {
                "total_failures"  : data["failed"],
                "total_successes" : data["success"],
                "lateral_events"  : data["lateral"],
                "privilege_events": data["privilege"],
                "rdp_attempts"    : data["rdp_attempts"],
                "users_count"     : len(data["users_targeted"]),
                "users_list"      : list(data["users_targeted"]),
                "logon_types"     : list(data["logon_types"]),
            },
            "indicators": {
                "fail_bursts"           : data["fail_bursts"],
                "brute_force_sequences" : len(data["suspicious_sequences"]),
                "off_hour_anomalies"    : data["off_hour_anomaly"],
                "lateral_movement_hits" : data["lateral"],
                "privilege_escalation"  : data["privilege"],
                "rdp_attacks"           : data["rdp_attempts"],
                "lateral_targets"       : []
            },
            "sequence_details" : data["suspicious_sequences"],
            "kill_chains"      : data["correlated_attacks"]
        }

    return output


# ──────────────────────────────────────────────
#  MAIN ENTRY POINT (for Flask)
# ──────────────────────────────────────────────

def run_windows_analysis(file_path):
    """
    Single entry point for Flask integration.
    Accepts .evtx, .xml, .csv, .txt Windows Event Log files.

    Usage in Flask:
        from windows_parser import run_windows_analysis
        result = run_windows_analysis("/tmp/security.evtx")
        return jsonify(result)
    """
    events, log_type = parse_windows_log(file_path)
    stats            = analyze_windows(events)
    report           = build_windows_report(stats)
    return report, log_type


# ──────────────────────────────────────────────
#  POWERSHELL EXPORT SCRIPT GENERATOR
# ──────────────────────────────────────────────

POWERSHELL_EXPORT_SCRIPT = r"""
# LogSentinel — Windows Event Log Export Script
# Run as Administrator in PowerShell

$OutputPath = "$env:TEMP\windows_security.xml"

Write-Host "[*] Exporting Windows Security Events..." -ForegroundColor Cyan

Get-WinEvent -LogName Security -FilterXPath `
    "*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672)]]" `
    -MaxEvents 5000 |
    ForEach-Object { $_.ToXml() } |
    Out-File $OutputPath -Encoding UTF8

Write-Host "[OK] Exported to: $OutputPath" -ForegroundColor Green
Write-Host "[*] Upload this file to LogSentinel File Upload tab" -ForegroundColor Yellow
"""

if __name__ == "__main__":
    print(POWERSHELL_EXPORT_SCRIPT)
