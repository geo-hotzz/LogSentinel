"""
╔══════════════════════════════════════════════════════════════╗
║   LogSentinel — Flask Web Service                            ║
║   Brute Force & Lateral Movement Detection                   ║
║   + Incident Response Alert Engine                           ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import json
import time
import paramiko
from datetime import datetime
from flask import Flask, request, render_template, jsonify, redirect, url_for
from werkzeug.utils import secure_filename
from apscheduler.schedulers.background import BackgroundScheduler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from correlation_engine import run_analysis
from windows_parser import run_windows_analysis, POWERSHELL_EXPORT_SCRIPT
from alerts import alert_engine, IR_PLAYBOOKS, PHASE_COLORS

UPLOAD_FOLDER      = "uploads"
WATCH_FOLDER       = "watched_logs"
RESULTS_FOLDER     = "results"
ALLOWED_EXTENSIONS = {"log", "txt", "out", "syslog"}
WINDOWS_EXTENSIONS = {"evtx", "xml", "csv"}
MAX_CONTENT_MB     = 50

SSH_CONFIG_DEFAULTS = {
    "host": "192.168.56.101", "port": 22,
    "username": "msfadmin",   "password": "msfadmin",
    "remote_path": "/var/log/auth.log", "interval_min": 5
}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"]      = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_MB * 1024 * 1024
app.secret_key = "logsentinel-secret-2025"

for folder in [UPLOAD_FOLDER, WATCH_FOLDER, RESULTS_FOLDER]:
    os.makedirs(folder, exist_ok=True)

state = {
    "latest_report": None, "latest_filename": None,
    "latest_timestamp": None, "scheduler_running": False,
    "scheduler_interval": SSH_CONFIG_DEFAULTS["interval_min"],
    "last_fetch_status": "Never fetched",
    "ssh_config": SSH_CONFIG_DEFAULTS.copy(),
    "watch_active": False, "activity_log": []
}

def log_activity(message, level="INFO"):
    entry = {"time": datetime.now().strftime("%H:%M:%S"), "level": level, "message": message}
    state["activity_log"].insert(0, entry)
    state["activity_log"] = state["activity_log"][:30]
    print(f"[{level}] {entry['time']} — {message}")

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def run_and_store(file_path, source_label):
    try:
        report  = run_analysis(file_path)
        summary = build_summary(report)
        state["latest_report"]    = {"report": report, "summary": summary}
        state["latest_filename"]  = source_label
        state["latest_timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state["last_fetch_status"] = f"Success at {state['latest_timestamp']}"
        result_file = os.path.join(RESULTS_FOLDER, f"result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(result_file, "w") as f:
            json.dump(state["latest_report"], f, indent=2, default=str)
        new_alerts = alert_engine.process_report(report, source_label)
        if new_alerts:
            log_activity(f"{len(new_alerts)} IR alert(s) — {sum(1 for a in new_alerts if a['severity']=='CRITICAL')} CRITICAL",
                "ERROR" if any(a["severity"]=="CRITICAL" for a in new_alerts) else "INFO")
        crit = sum(1 for e in report.values() if e["risk_level"] == "CRITICAL")
        log_activity(f"Analysis done — {source_label} — {len(report)} IPs — {crit} CRITICAL", "SUCCESS")
        return report, summary, new_alerts
    except Exception as e:
        state["last_fetch_status"] = f"Failed: {str(e)}"
        log_activity(f"Analysis failed — {str(e)}", "ERROR")
        return None, None, []

def build_summary(report):
    critical  = sum(1 for e in report.values() if e["risk_level"] == "CRITICAL")
    high      = sum(1 for e in report.values() if e["risk_level"] == "HIGH")
    suspicious= sum(1 for e in report.values() if e["risk_level"] == "SUSPICIOUS")
    normal    = sum(1 for e in report.values() if e["risk_level"] == "NORMAL")
    ip_list   = sorted(report.values(), key=lambda x: x["risk_score"], reverse=True)[:10]
    return {
        "totals": {
            "ips": len(report), "critical": critical, "high": high,
            "suspicious": suspicious, "normal": normal,
            "failed": sum(e["summary"]["total_failures"] for e in report.values()),
            "success": sum(e["summary"]["total_successes"] for e in report.values()),
            "kill_chains": sum(len(e["kill_chains"]) for e in report.values()),
            "lateral": sum(e["indicators"]["lateral_movement_hits"] for e in report.values())
        },
        "charts": {
            "labels": [e["ip"] for e in ip_list],
            "scores": [e["risk_score"] for e in ip_list],
            "failed": [e["summary"]["total_failures"] for e in ip_list],
            "success":[e["summary"]["total_successes"] for e in ip_list],
            "levels": [e["risk_level"] for e in ip_list]
        },
        "risk_dist": {
            "labels": ["CRITICAL","HIGH","SUSPICIOUS","NORMAL"],
            "data":   [critical, high, suspicious, normal],
            "colors": ["#ff2d2d","#ff6b35","#ffd700","#00ff88"]
        }
    }

def fetch_via_ssh(cfg=None):
    if cfg is None: cfg = state["ssh_config"]
    log_activity(f"SSH fetch → {cfg['host']}:{cfg['remote_path']}", "INFO")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=cfg["host"], port=int(cfg["port"]),
            username=cfg["username"], password=cfg["password"], timeout=10)
        save_path = os.path.join(UPLOAD_FOLDER, "ssh_fetched_auth.log")
        sftp = client.open_sftp()
        sftp.get(cfg["remote_path"], save_path)
        sftp.close(); client.close()
        log_activity(f"SSH fetch success from {cfg['host']}", "SUCCESS")
        run_and_store(save_path, f"SSH:{cfg['host']}")
        return True, "Fetched and analyzed successfully"
    except paramiko.AuthenticationException:
        msg = "SSH auth failed — check username/password"
    except Exception as e:
        msg = f"SSH error: {str(e)}"
    log_activity(msg, "ERROR")
    return False, msg

class LogFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory: self._handle(event.src_path)
    def on_modified(self, event):
        if not event.is_directory: self._handle(event.src_path)
    def _handle(self, path):
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if ext in ALLOWED_EXTENSIONS:
            log_activity(f"Watcher: {os.path.basename(path)}", "INFO")
            time.sleep(0.5)
            run_and_store(path, f"WATCH:{os.path.basename(path)}")

observer = Observer()
observer.schedule(LogFileHandler(), WATCH_FOLDER, recursive=False)
observer.start()
state["watch_active"] = True
log_activity(f"Folder watcher active → {WATCH_FOLDER}/", "INFO")

scheduler = BackgroundScheduler()
def scheduled_ssh_fetch():
    log_activity("Scheduled SSH fetch triggered", "INFO")
    fetch_via_ssh()

# ── ROUTES ──────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", state=state, ssh_config=state["ssh_config"],
        alert_summary=alert_engine.get_alert_summary(), email_config=alert_engine.email_config)

@app.route("/dashboard")
def dashboard():
    if not state["latest_report"]: return redirect(url_for("index"))
    report = state["latest_report"]["report"]
    summary = state["latest_report"]["summary"]
    sorted_report = dict(sorted(report.items(), key=lambda x: x[1]["risk_score"], reverse=True))
    return render_template("dashboard.html", report=sorted_report, summary=summary,
        filename=state["latest_filename"], timestamp=state["latest_timestamp"],
        alerts=alert_engine.alerts[:20], alert_summary=alert_engine.get_alert_summary(),
        phase_colors=PHASE_COLORS)

@app.route("/alerts")
def alerts_page():
    alert_engine.mark_all_read()
    return render_template("alerts.html", alerts=alert_engine.alerts,
        alert_summary=alert_engine.get_alert_summary(), phase_colors=PHASE_COLORS)

@app.route("/upload", methods=["POST"])
def upload():
    if "logfile" not in request.files: return jsonify({"error":"No file provided"}), 400
    file = request.files["logfile"]
    if not file.filename or not allowed_file(file.filename): return jsonify({"error":"Invalid file"}), 400
    filename = secure_filename(file.filename)
    upload_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(upload_path)
    log_activity(f"File uploaded: {filename}", "INFO")
    report, summary, new_alerts = run_and_store(upload_path, filename)
    if report:
        return jsonify({"success":True, "redirect":"/dashboard", "new_alerts":len(new_alerts),
            "alerts":[{"title":a["title"],"severity":a["severity"],"ip":a["ip"]} for a in new_alerts]})
    return jsonify({"error": state["last_fetch_status"]}), 500

@app.route("/ssh-fetch", methods=["POST"])
def ssh_fetch():
    data = request.get_json() or {}
    cfg  = {k: data.get(k, state["ssh_config"][k]) for k in ["host","port","username","password","remote_path"]}
    state["ssh_config"].update(cfg)
    success, message = fetch_via_ssh(cfg)
    if success: return jsonify({"success":True,"message":message,"redirect":"/dashboard"})
    return jsonify({"success":False,"message":message}), 500

@app.route("/paste", methods=["POST"])
def paste():
    data    = request.get_json() or {}
    content = data.get("content","").strip()
    if not content or len(content) < 50: return jsonify({"error":"Content too short"}), 400
    paste_path = os.path.join(UPLOAD_FOLDER, "pasted_log.log")
    with open(paste_path,"w") as f: f.write(content)
    log_activity(f"Pasted log — {len(content.splitlines())} lines", "INFO")
    report, summary, new_alerts = run_and_store(paste_path, "PASTED_LOG")
    if report: return jsonify({"success":True,"redirect":"/dashboard","new_alerts":len(new_alerts)})
    return jsonify({"error": state["last_fetch_status"]}), 500



@app.route("/winrm-fetch", methods=["POST"])
def winrm_fetch():
    """Pull Windows Event Logs via WinRM (Windows Remote Management)."""
    data = request.get_json() or {}
    host     = data.get("host", "")
    username = data.get("username", "")
    password = data.get("password", "")
    use_ssl  = data.get("use_ssl", False)

    if not host or not username:
        return jsonify({"error": "Host and username required"}), 400

    log_activity(f"WinRM fetch → {host}", "INFO")
    try:
        import winrm
        protocol = "https" if use_ssl else "http"
        port     = 5986 if use_ssl else 5985

        session = winrm.Session(
            f"{protocol}://{host}:{port}/wsman",
            auth=(username, password),
            transport="ntlm",
            server_cert_validation="ignore"
        )

        # Run PowerShell to export security events
        ps_script = """
$events = Get-WinEvent -LogName Security -FilterXPath `
    '*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672)]]' `
    -MaxEvents 2000 -ErrorAction SilentlyContinue
$events | ForEach-Object { $_.ToXml() }
"""
        result = session.run_ps(ps_script)

        if result.status_code != 0:
            error_msg = result.std_err.decode("utf-8", errors="replace")
            return jsonify({"error": f"PowerShell error: {error_msg}"}), 500

        xml_output = result.std_out.decode("utf-8", errors="replace")
        if not xml_output.strip():
            return jsonify({"error": "No events returned from Windows host"}), 400

        # Save and analyze
        save_path = os.path.join(UPLOAD_FOLDER, f"winrm_{host.replace('.','_')}.xml")
        with open(save_path, "w", encoding="utf-8") as f:
            f.write("<Events>\n" + xml_output + "\n</Events>")

        log_activity(f"WinRM fetch success from {host}", "SUCCESS")
        report, summary, new_alerts = run_and_store(save_path, f"WIN:{host}")
        if report:
            return jsonify({"success": True, "redirect": "/dashboard",
                           "new_alerts": len(new_alerts)})
        return jsonify({"error": state["last_fetch_status"]}), 500

    except ImportError:
        return jsonify({"error": "pywinrm not installed. Run: pip install pywinrm"}), 500
    except Exception as e:
        log_activity(f"WinRM error: {str(e)}", "ERROR")
        return jsonify({"error": f"WinRM error: {str(e)}"}), 500


@app.route("/api/powershell-script")
def powershell_script():
    """Return PowerShell export script for manual Windows log collection."""
    from windows_parser import POWERSHELL_EXPORT_SCRIPT
    return jsonify({"script": POWERSHELL_EXPORT_SCRIPT})

@app.route("/scheduler/start", methods=["POST"])
def scheduler_start():
    data = request.get_json() or {}
    interval = int(data.get("interval", state["scheduler_interval"]))
    if state["scheduler_running"]: scheduler.remove_all_jobs()
    scheduler.add_job(scheduled_ssh_fetch,"interval",minutes=interval,id="ssh_job")
    if not scheduler.running: scheduler.start()
    state["scheduler_running"] = True
    state["scheduler_interval"] = interval
    log_activity(f"Scheduler started — every {interval} min","INFO")
    return jsonify({"success":True,"message":f"Scheduler running every {interval} minutes"})

@app.route("/scheduler/stop", methods=["POST"])
def scheduler_stop():
    if scheduler.running: scheduler.remove_all_jobs()
    state["scheduler_running"] = False
    log_activity("Scheduler stopped","INFO")
    return jsonify({"success":True,"message":"Scheduler stopped"})

@app.route("/api/alerts")
def api_alerts():
    return jsonify({"alerts":alert_engine.alerts[:20],"summary":alert_engine.get_alert_summary()})

@app.route("/api/alerts/clear", methods=["POST"])
def clear_alerts():
    alert_engine.clear_alerts()
    return jsonify({"success":True})

@app.route("/api/alerts/read/<int:alert_id>", methods=["POST"])
def mark_read(alert_id):
    alert_engine.mark_read(alert_id)
    return jsonify({"success":True})

@app.route("/api/email/configure", methods=["POST"])
def configure_email():
    data = request.get_json() or {}
    alert_engine.configure_email({
        "enabled": data.get("enabled",False), "smtp_host": data.get("smtp_host","smtp.gmail.com"),
        "smtp_port": int(data.get("smtp_port",587)), "sender": data.get("sender",""),
        "password": data.get("password",""), "recipient": data.get("recipient","")
    })
    log_activity(f"Email {'enabled' if data.get('enabled') else 'disabled'}","INFO")
    return jsonify({"success":True,"message":"Email configuration saved"})

@app.route("/api/email/test", methods=["POST"])
def test_email():
    success, message = alert_engine.test_email()
    return jsonify({"success":success,"message":message})

@app.route("/api/status")
def api_status():
    return jsonify({
        "scheduler_running": state["scheduler_running"], "scheduler_interval": state["scheduler_interval"],
        "last_fetch_status": state["last_fetch_status"], "latest_timestamp": state["latest_timestamp"],
        "latest_filename": state["latest_filename"], "watch_active": state["watch_active"],
        "activity_log": state["activity_log"][:10], "alert_summary": alert_engine.get_alert_summary()
    })

if __name__ == "__main__":
    print("\n" + "="*58)
    print("  LogSentinel — Automated Correlation System")
    print("  http://127.0.0.1:5000")
    print("="*58)
    print(f"  Watch Folder : {os.path.abspath(WATCH_FOLDER)}")
    print(f"  IR Alerts    : Browser + Email + Sound")
    print("="*58 + "\n")
    try:
        app.run(debug=False, host="127.0.0.1", port=5000, use_reloader=False)
    finally:
        observer.stop(); observer.join()
        if scheduler.running: scheduler.shutdown()
