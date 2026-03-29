"""
╔══════════════════════════════════════════════════════════════╗
║   LogSentinel — Incident Response Alert Engine               ║
║                                                              ║
║   Alert Types:                                               ║
║     - Browser push notifications                             ║
║     - Email alerts (SMTP/Gmail)                              ║
║     - Sound trigger signals                                  ║
║     - Alert log with IR playbook steps                       ║
║                                                              ║
║   Triggers:                                                  ║
║     - CRITICAL risk IP detected                              ║
║     - Kill chain assembled                                   ║
║     - Lateral movement detected                              ║
║     - Brute force burst detected                             ║
╚══════════════════════════════════════════════════════════════╝
"""

import json
import smtplib
import os
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ──────────────────────────────────────────────
#  IR PLAYBOOKS
#  Each trigger type has a defined response plan
# ──────────────────────────────────────────────

IR_PLAYBOOKS = {

    "KILL_CHAIN": {
        "title"      : "Full Kill Chain Detected",
        "severity"   : "CRITICAL",
        "description": "A complete attack chain was confirmed: Brute Force → Initial Access → Lateral Movement.",
        "mitre"      : ["T1110.001", "T1078", "T1021.004"],
        "steps": [
            {
                "phase"  : "CONTAIN",
                "actions": [
                    "Immediately block attacker IP at the firewall",
                    "Terminate all active SSH sessions from the attacker IP",
                    "Isolate the compromised host from the network if possible",
                    "Revoke credentials of the compromised user account"
                ]
            },
            {
                "phase"  : "INVESTIGATE",
                "actions": [
                    "Review full auth.log for all activity from attacker IP",
                    "Check /var/log/syslog for post-login commands executed",
                    "Identify all systems the attacker pivoted to",
                    "Determine the initial entry point and attack timeline",
                    "Check for new user accounts or cron jobs created"
                ]
            },
            {
                "phase"  : "ERADICATE",
                "actions": [
                    "Remove any backdoors or persistence mechanisms",
                    "Reset all compromised user passwords",
                    "Patch or update the vulnerable SSH service",
                    "Review and harden SSH configuration (/etc/ssh/sshd_config)"
                ]
            },
            {
                "phase"  : "RECOVER",
                "actions": [
                    "Restore system from last clean backup if required",
                    "Re-enable services after confirming clean state",
                    "Monitor for re-infection for 72 hours post-incident",
                    "Update detection rules based on attacker TTPs"
                ]
            }
        ]
    },

    "LATERAL_MOVEMENT": {
        "title"      : "Lateral Movement Detected",
        "severity"   : "HIGH",
        "description": "A compromised host is initiating new SSH connections to other systems.",
        "mitre"      : ["T1021.004"],
        "steps": [
            {
                "phase"  : "CONTAIN",
                "actions": [
                    "Block outbound SSH connections from the compromised host",
                    "Identify all target IPs the pivot was attempted against",
                    "Isolate the pivot source host immediately"
                ]
            },
            {
                "phase"  : "INVESTIGATE",
                "actions": [
                    "Review SSH known_hosts on the compromised system",
                    "Check bash history for commands run post-compromise",
                    "Identify whether pivoted targets were also compromised",
                    "Correlate timestamps with auth.log on target systems"
                ]
            },
            {
                "phase"  : "ERADICATE",
                "actions": [
                    "Remove attacker-placed SSH keys from authorized_keys",
                    "Terminate all rogue SSH sessions",
                    "Reset credentials on all affected systems"
                ]
            },
            {
                "phase"  : "RECOVER",
                "actions": [
                    "Verify integrity of all systems reachable from compromised host",
                    "Implement network segmentation to prevent future pivoting",
                    "Enable SSH key-only authentication, disable passwords"
                ]
            }
        ]
    },

    "BRUTE_FORCE": {
        "title"      : "Brute Force Burst Detected",
        "severity"   : "HIGH",
        "description": "High-frequency SSH login failures detected from a single IP within a short window.",
        "mitre"      : ["T1110.001"],
        "steps": [
            {
                "phase"  : "CONTAIN",
                "actions": [
                    "Block attacker IP using iptables or firewall rule",
                    "Enable fail2ban if not already active",
                    "Consider rate-limiting SSH connections per IP"
                ]
            },
            {
                "phase"  : "INVESTIGATE",
                "actions": [
                    "Check if any login attempts were successful after the burst",
                    "Review targeted usernames for credential stuffing patterns",
                    "Determine if the IP belongs to known threat actors (check AbuseIPDB)"
                ]
            },
            {
                "phase"  : "ERADICATE",
                "actions": [
                    "Permanently blacklist the attacking IP range",
                    "Enforce account lockout policies",
                    "Remove any weak or default credentials"
                ]
            },
            {
                "phase"  : "RECOVER",
                "actions": [
                    "Change SSH port from default 22 if not already done",
                    "Enable multi-factor authentication for SSH",
                    "Review and strengthen password policies"
                ]
            }
        ]
    },

    "CRITICAL_IP": {
        "title"      : "Critical Risk IP Detected",
        "severity"   : "CRITICAL",
        "description": "An IP address has reached CRITICAL risk score across multiple detection indicators.",
        "mitre"      : ["T1110", "T1078"],
        "steps": [
            {
                "phase"  : "CONTAIN",
                "actions": [
                    "Immediately block the IP at the network perimeter",
                    "Alert network team to apply block across all entry points",
                    "Check if the IP is active in any current sessions"
                ]
            },
            {
                "phase"  : "INVESTIGATE",
                "actions": [
                    "Review all events associated with this IP",
                    "Cross-reference IP against threat intelligence feeds",
                    "Identify all systems this IP has interacted with",
                    "Check WHOIS and geolocation for attribution context"
                ]
            },
            {
                "phase"  : "ERADICATE",
                "actions": [
                    "Remove any access granted to this IP",
                    "Audit all accounts targeted by this IP",
                    "Ensure no persistence mechanisms were established"
                ]
            },
            {
                "phase"  : "RECOVER",
                "actions": [
                    "Document incident for threat intelligence sharing",
                    "Update firewall blocklists with this IP and related ranges",
                    "Review detection thresholds and tune scoring engine"
                ]
            }
        ]
    }
}

# Phase colors for UI display
PHASE_COLORS = {
    "CONTAIN"    : "#ff2d2d",
    "INVESTIGATE": "#ff6b35",
    "ERADICATE"  : "#ffd700",
    "RECOVER"    : "#00ff88"
}

# ──────────────────────────────────────────────
#  ALERT ENGINE
# ──────────────────────────────────────────────

class AlertEngine:
    def __init__(self):
        self.alerts       = []        # All generated alerts
        self.unread_count = 0         # Badge count for UI
        self.email_config = {
            "enabled"  : False,
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "sender"   : "",
            "password" : "",
            "recipient": ""
        }

    # ── Alert Generation ────────────────────────

    def process_report(self, report, filename):
        """
        Scan analysis report and generate alerts
        for all triggered conditions.
        Returns list of new alerts generated.
        """
        new_alerts = []

        for ip, data in report.items():
            level     = data["risk_level"]
            score     = data["risk_score"]
            ind       = data["indicators"]
            chains    = data["kill_chains"]

            # Trigger: Kill Chain
            if chains:
                alert = self._create_alert(
                    trigger  = "KILL_CHAIN",
                    ip       = ip,
                    filename = filename,
                    detail   = f"{len(chains)} kill chain(s) confirmed — "
                               f"User: {data['summary']['users_list']}"
                )
                new_alerts.append(alert)

            # Trigger: Lateral Movement
            elif ind["lateral_movement_hits"] > 0:
                alert = self._create_alert(
                    trigger  = "LATERAL_MOVEMENT",
                    ip       = ip,
                    filename = filename,
                    detail   = f"{ind['lateral_movement_hits']} pivot(s) to: "
                               f"{ind['lateral_targets']}"
                )
                new_alerts.append(alert)

            # Trigger: Critical IP (no kill chain but critical score)
            elif level == "CRITICAL":
                alert = self._create_alert(
                    trigger  = "CRITICAL_IP",
                    ip       = ip,
                    filename = filename,
                    detail   = f"Risk score: {score} — "
                               f"{data['summary']['total_failures']} failures"
                )
                new_alerts.append(alert)

            # Trigger: Brute Force Burst
            elif ind["fail_bursts"] > 0:
                alert = self._create_alert(
                    trigger  = "BRUTE_FORCE",
                    ip       = ip,
                    filename = filename,
                    detail   = f"{ind['fail_bursts']} burst(s) — "
                               f"{data['summary']['total_failures']} total failures"
                )
                new_alerts.append(alert)

        # Send emails for new alerts
        if self.email_config["enabled"] and new_alerts:
            self._send_email_batch(new_alerts)

        return new_alerts


    def _create_alert(self, trigger, ip, filename, detail):
        """Build a single alert record with playbook."""
        playbook = IR_PLAYBOOKS.get(trigger, {})
        alert = {
            "id"        : len(self.alerts) + 1,
            "trigger"   : trigger,
            "ip"        : ip,
            "filename"  : filename,
            "detail"    : detail,
            "severity"  : playbook.get("severity", "HIGH"),
            "title"     : playbook.get("title", trigger),
            "description": playbook.get("description", ""),
            "mitre"     : playbook.get("mitre", []),
            "steps"     : playbook.get("steps", []),
            "timestamp" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "read"      : False
        }
        self.alerts.insert(0, alert)
        self.alerts = self.alerts[:100]   # Keep last 100
        self.unread_count += 1
        return alert


    def mark_all_read(self):
        for a in self.alerts:
            a["read"] = True
        self.unread_count = 0


    def mark_read(self, alert_id):
        for a in self.alerts:
            if a["id"] == alert_id:
                a["read"] = True
                if self.unread_count > 0:
                    self.unread_count -= 1
                break


    def clear_alerts(self):
        self.alerts       = []
        self.unread_count = 0


    # ── Email ────────────────────────────────────

    def configure_email(self, cfg):
        self.email_config.update(cfg)


    def test_email(self):
        """Send a test email to verify config."""
        if not self.email_config["enabled"]:
            return False, "Email not enabled"
        try:
            self._send_email(
                subject = "[LogSentinel] Test Alert — Email Config Working",
                body    = self._build_email_body({
                    "title"    : "Test Alert",
                    "severity" : "INFO",
                    "ip"       : "0.0.0.0",
                    "detail"   : "This is a test alert from LogSentinel.",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "mitre"    : [],
                    "steps"    : []
                })
            )
            return True, "Test email sent successfully"
        except Exception as e:
            return False, f"Email failed: {str(e)}"


    def _send_email_batch(self, alerts):
        """Send email for each alert."""
        for alert in alerts:
            try:
                self._send_email(
                    subject = f"[LogSentinel] {alert['severity']} — {alert['title']} — {alert['ip']}",
                    body    = self._build_email_body(alert)
                )
            except Exception as e:
                print(f"[ERROR] Email failed for alert {alert['id']}: {e}")


    def _send_email(self, subject, body):
        cfg = self.email_config
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = cfg["sender"]
        msg["To"]      = cfg["recipient"]
        msg.attach(MIMEText(body, "html"))

        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"]) as server:
            server.starttls()
            server.login(cfg["sender"], cfg["password"])
            server.sendmail(cfg["sender"], cfg["recipient"], msg.as_string())


    def _build_email_body(self, alert):
        """Build HTML email body."""
        severity_colors = {
            "CRITICAL": "#ff2d2d",
            "HIGH"    : "#ff6b35",
            "INFO"    : "#00e5ff"
        }
        color = severity_colors.get(alert.get("severity", "HIGH"), "#ff6b35")

        mitre_badges = "".join([
            f'<span style="display:inline-block;padding:2px 8px;margin:2px;'
            f'border:1px solid #00e5ff;color:#00e5ff;font-size:11px;'
            f'border-radius:2px;">{t}</span>'
            for t in alert.get("mitre", [])
        ])

        steps_html = ""
        for step in alert.get("steps", []):
            phase_color = PHASE_COLORS.get(step["phase"], "#4a5568")
            actions_html = "".join([
                f'<li style="margin-bottom:4px;">{a}</li>'
                for a in step["actions"]
            ])
            steps_html += f"""
            <div style="margin-bottom:12px;">
              <div style="color:{phase_color};font-weight:bold;
                font-size:11px;letter-spacing:2px;margin-bottom:6px;">
                ▸ {step['phase']}
              </div>
              <ul style="margin:0;padding-left:20px;color:#c9d1d9;font-size:12px;">
                {actions_html}
              </ul>
            </div>"""

        return f"""
        <html><body style="background:#070b0f;color:#c9d1d9;
          font-family:'Courier New',monospace;padding:20px;">
          <div style="max-width:600px;margin:0 auto;">

            <div style="border-left:4px solid {color};padding:16px;
              background:#0d1117;margin-bottom:16px;">
              <div style="color:{color};font-size:11px;letter-spacing:2px;
                margin-bottom:4px;">[{alert.get('severity','HIGH')}] LOGSENTINEL ALERT</div>
              <div style="font-size:18px;font-weight:bold;color:#fff;
                margin-bottom:4px;">{alert.get('title','Alert')}</div>
              <div style="color:#4a5568;font-size:11px;">{alert.get('timestamp','')}</div>
            </div>

            <table style="width:100%;border-collapse:collapse;margin-bottom:16px;">
              <tr>
                <td style="padding:8px;background:#0a0f15;border:1px solid #1a2535;
                  color:#4a5568;font-size:11px;width:120px;">ATTACKER IP</td>
                <td style="padding:8px;background:#0d1117;border:1px solid #1a2535;
                  color:#00e5ff;">{alert.get('ip','')}</td>
              </tr>
              <tr>
                <td style="padding:8px;background:#0a0f15;border:1px solid #1a2535;
                  color:#4a5568;font-size:11px;">LOG SOURCE</td>
                <td style="padding:8px;background:#0d1117;border:1px solid #1a2535;">
                  {alert.get('filename','')}</td>
              </tr>
              <tr>
                <td style="padding:8px;background:#0a0f15;border:1px solid #1a2535;
                  color:#4a5568;font-size:11px;">DETAIL</td>
                <td style="padding:8px;background:#0d1117;border:1px solid #1a2535;">
                  {alert.get('detail','')}</td>
              </tr>
            </table>

            {f'<div style="margin-bottom:16px;">{mitre_badges}</div>' if mitre_badges else ''}

            <div style="color:#4a5568;font-size:11px;letter-spacing:2px;
              margin-bottom:8px;">INCIDENT RESPONSE PLAYBOOK</div>
            <div style="background:#0d1117;border:1px solid #1a2535;padding:16px;">
              {steps_html if steps_html else '<p style="color:#4a5568;">No playbook available.</p>'}
            </div>

            <div style="margin-top:16px;padding:8px;border-top:1px solid #1a2535;
              color:#4a5568;font-size:10px;text-align:center;">
              LogSentinel — Automated Correlation System
            </div>
          </div>
        </body></html>"""


    def get_alert_summary(self):
        """Return counts for UI badge."""
        return {
            "total"   : len(self.alerts),
            "unread"  : self.unread_count,
            "critical": sum(1 for a in self.alerts if a["severity"] == "CRITICAL"),
            "high"    : sum(1 for a in self.alerts if a["severity"] == "HIGH")
        }


# ── Global alert engine instance ──────────────
alert_engine = AlertEngine()
