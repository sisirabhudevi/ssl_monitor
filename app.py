import json
import os
import ssl
import socket
import smtplib
import threading
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, date, timedelta

from flask import Flask, render_template, request, redirect, url_for, jsonify

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

CONFIG_FILE  = os.path.join(os.path.dirname(__file__), "config.json")
ALERTS_FILE  = os.path.join(os.path.dirname(__file__), "alerts_sent.json")
WARN_DAYS    = 30
SCAN_TIMES   = ((7, 35), (19, 35))  # scan 25 min early so alerts land by 8am and 8pm

_last_scan_time     = None
_last_scan_duration = None
_scan_lock          = threading.Lock()


# ── Config ───────────────────────────────────────────────────────────────────

def load_config():
    if os.path.exists(CONFIG_FILE):
        cfg = json.load(open(CONFIG_FILE))
        cfg.setdefault("smtp_host", "")
        cfg.setdefault("smtp_port", 587)
        cfg.setdefault("smtp_user", "")
        cfg.setdefault("smtp_password", "")
        cfg.setdefault("alert_from", "")
        cfg.setdefault("domain_owners", {})
        return cfg
    return {
        "smtp_host": "", "smtp_port": 587, "smtp_user": "",
        "smtp_password": "", "alert_from": "", "domain_owners": {},
    }


def save_config(smtp_host, smtp_port, smtp_user, smtp_password, alert_from, domain_owners_raw):
    owners = {}
    for line in domain_owners_raw.splitlines():
        if ":" in line:
            domain, email = line.split(":", 1)
            domain = domain.strip().lower()
            email  = email.strip()
            if domain and email:
                owners[domain] = email
    with open(CONFIG_FILE, "w") as f:
        json.dump({
            "smtp_host": smtp_host, "smtp_port": int(smtp_port or 587),
            "smtp_user": smtp_user, "smtp_password": smtp_password,
            "alert_from": alert_from, "domain_owners": owners,
        }, f, indent=2)


# ── Cert check ───────────────────────────────────────────────────────────────

def check_cert(domain, port=443):
    """Return (expiry_date, days_left, error_str)."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((domain, port), timeout=10),
                             server_hostname=domain) as s:
            cert = s.getpeercert()
        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days   = (expiry - datetime.utcnow()).days
        return expiry.strftime("%Y-%m-%d"), days, None
    except Exception as e:
        return None, None, str(e)


def _should_alert(domain, days):
    if days is None:
        return None
    if days < 0:
        return f"{domain} — certificate EXPIRED"
    if days <= WARN_DAYS:
        return f"{domain} — expires in {days} day{'s' if days != 1 else ''}"
    return None


# ── Alert dedup ──────────────────────────────────────────────────────────────

def _load_alerts():
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE) as f:
            return json.load(f)
    return {}


def _save_alerts(alerts):
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=2)


# ── Email ────────────────────────────────────────────────────────────────────

def _send_email(config, to_address, subject, body_text, body_html=None):
    host     = config.get("smtp_host", "")
    port     = int(config.get("smtp_port", 587))
    user     = config.get("smtp_user", "")
    password = config.get("smtp_password", "")
    from_addr = config.get("alert_from", "") or user

    if not host or not user or not to_address:
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"cert-pulse <{from_addr}>"
    msg["To"]      = to_address

    msg.attach(MIMEText(body_text, "plain"))
    if body_html:
        msg.attach(MIMEText(body_html, "html"))

    try:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(user, password)
            smtp.sendmail(from_addr, [to_address], msg.as_string())
    except Exception:
        pass


def _build_email_body(msgs, now_str):
    plain = "\n".join(f"  - {m}" for m in msgs)
    plain += f"\n\nGenerated: {now_str}\ncert-pulse"

    rows = "".join(
        f"<tr><td style='padding:8px 12px;border-bottom:1px solid #eee'>{m}</td></tr>"
        for m in msgs
    )
    html = f"""<div style="font-family:sans-serif;max-width:520px">
  <h2 style="color:#c0392b;margin-bottom:4px">SSL Certificate Alert</h2>
  <table style="width:100%;border-collapse:collapse;margin-top:12px">
    {rows}
  </table>
  <p style="color:#999;font-size:12px;margin-top:20px">
    Generated: {now_str} &nbsp;·&nbsp; cert-pulse
  </p>
</div>"""
    return plain, html


# ── Background monitor ───────────────────────────────────────────────────────

def run_monitor():
    global _last_scan_time, _last_scan_duration
    _t0 = time.time()
    with _scan_lock:
        config    = load_config()
        smtp_host = config.get("smtp_host", "")

        if not smtp_host:
            _last_scan_time = datetime.now()
            return

        owners_map = config.get("domain_owners", {})
        domains    = list(owners_map.keys())
        if not domains:
            _last_scan_time = datetime.now()
            return

        alerts     = _load_alerts()
        slot       = "am" if datetime.now().hour < 12 else "pm"
        today_slot = f"{date.today()}-{slot}"
        changed    = False

        by_owner = {}

        for domain in domains:
            expiry_date, days, error = check_cert(domain)
            if error:
                continue
            msg = _should_alert(domain, days)
            if msg and alerts.get(domain) != today_slot:
                owner_email = owners_map.get(domain.lower(), "")
                label = f"{msg} (expires {expiry_date})"
                by_owner.setdefault(owner_email, []).append(label)
                alerts[domain] = today_slot
                changed = True

        if by_owner:
            now_str = datetime.now().strftime("%Y-%m-%d %I:%M %p")
            for owner_email, msgs in by_owner.items():
                if not owner_email:
                    continue
                subject = f"SSL Alert: {len(msgs)} certificate{'s' if len(msgs) != 1 else ''} need attention"
                plain, html = _build_email_body(msgs, now_str)
                _send_email(config, owner_email, subject, plain, html)

        if changed:
            _save_alerts(alerts)

        _last_scan_time     = datetime.now()
        _last_scan_duration = round(time.time() - _t0)


def _monitor_loop():
    while True:
        now        = datetime.now()
        candidates = [now.replace(hour=h, minute=m, second=0, microsecond=0)
                      for h, m in SCAN_TIMES]
        future     = [t for t in candidates if t > now]
        next_run   = future[0] if future else (now + timedelta(days=1)).replace(
            hour=SCAN_TIMES[0][0], minute=SCAN_TIMES[0][1], second=0, microsecond=0)
        time.sleep((next_run - datetime.now()).total_seconds())
        try:
            run_monitor()
        except Exception:
            pass


if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
    threading.Thread(target=_monitor_loop, daemon=True).start()


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", config=load_config())


@app.route("/check", methods=["POST"])
def check():
    domain = request.form.get("domain", "").strip()
    expiry_date, days, error = check_cert(domain)
    return jsonify({"domain": domain, "expiry": expiry_date, "days": days, "error": error})


@app.route("/scan_now", methods=["POST"])
def scan_now():
    if _scan_lock.locked():
        return jsonify({"ok": False, "reason": "scan already in progress"})
    threading.Thread(target=run_monitor, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/monitor_status", methods=["GET"])
def monitor_status():
    return jsonify({
        "last_scan": _last_scan_time.isoformat() if _last_scan_time else None,
        "scan_duration": _last_scan_duration,
    })


@app.route("/domains", methods=["GET"])
def get_domains():
    config  = load_config()
    owners  = config.get("domain_owners", {})
    alerts  = _load_alerts()
    results = []
    for domain, owner_email in owners.items():
        expiry_date, days, error = check_cert(domain)
        results.append({
            "domain":  domain,
            "owner":   owner_email or "—",
            "expiry":  expiry_date,
            "days":    days,
            "error":   error,
            "alerted": alerts.get(domain),
        })
    return jsonify(results)


@app.route("/save_settings", methods=["POST"])
def save_settings():
    save_config(
        request.form.get("smtp_host", "").strip(),
        request.form.get("smtp_port", "587").strip(),
        request.form.get("smtp_user", "").strip(),
        request.form.get("smtp_password", "").strip(),
        request.form.get("alert_from", "").strip(),
        request.form.get("domain_owners_raw", "").strip(),
    )
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=False, port=5051)
