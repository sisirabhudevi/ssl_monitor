import json
import os
import ssl
import socket
import threading
import time
import requests
from datetime import datetime, date, timedelta

from flask import Flask, render_template, request, redirect, url_for, jsonify

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True

CONFIG_FILE  = os.path.join(os.path.dirname(__file__), "config.json")
ALERTS_FILE  = os.path.join(os.path.dirname(__file__), "alerts_sent.json")
DOMAINS_FILE = os.path.join(os.path.dirname(__file__), "domains.json")
WARN_DAYS    = 30
SCAN_TIMES   = ((7, 35), (19, 35))  # scan 25 min early so alerts land by 8am and 8pm

_last_scan_time     = None
_last_scan_duration = None
_scan_lock          = threading.Lock()


# ── Config ───────────────────────────────────────────────────────────────────

def load_config():
    if os.path.exists(CONFIG_FILE):
        cfg = json.load(open(CONFIG_FILE))
        cfg.setdefault("slack_webhook", "")
        cfg.setdefault("slack_bot_token", "")
        cfg.setdefault("domain_owners", {})
        return cfg
    return {"slack_webhook": "", "slack_bot_token": "", "domain_owners": {}}


def save_config(slack_webhook, slack_bot_token, domain_owners_raw):
    owners = {}
    for line in domain_owners_raw.splitlines():
        if ":" in line:
            domain, email = line.split(":", 1)
            domain = domain.strip().lower()
            email  = email.strip()
            if domain and email:
                owners[domain] = email
    with open(CONFIG_FILE, "w") as f:
        json.dump({"slack_webhook": slack_webhook,
                   "slack_bot_token": slack_bot_token,
                   "domain_owners": owners}, f, indent=2)


def load_domains():
    if os.path.exists(DOMAINS_FILE):
        return json.load(open(DOMAINS_FILE))
    return []


def save_domains(domains):
    with open(DOMAINS_FILE, "w") as f:
        json.dump(domains, f, indent=2)


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
        return f"*{domain}* — certificate EXPIRED"
    if days <= WARN_DAYS:
        return f"*{domain}* — expires in {days} day{'s' if days != 1 else ''}"
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


# ── Slack ────────────────────────────────────────────────────────────────────

_slack_uid_cache = {}

def _slack_uid_for_email(email, bot_token):
    if email in _slack_uid_cache:
        return _slack_uid_cache[email]
    try:
        r = requests.get(
            "https://slack.com/api/users.lookupByEmail",
            headers={"Authorization": f"Bearer {bot_token}"},
            params={"email": email},
            timeout=10,
        )
        data = r.json()
        if data.get("ok"):
            uid = data["user"]["id"]
            _slack_uid_cache[email] = uid
            return uid
    except Exception:
        pass
    return None


def _post_slack(webhook, text):
    try:
        requests.post(webhook, json={"text": text}, timeout=10)
    except Exception:
        pass


# ── Background monitor ───────────────────────────────────────────────────────

def run_monitor():
    global _last_scan_time, _last_scan_duration
    _t0 = time.time()
    with _scan_lock:
        config    = load_config()
        webhook   = config.get("slack_webhook", "")
        bot_token = config.get("slack_bot_token", "")

        if not webhook and not bot_token:
            _last_scan_time = datetime.now()
            return

        owners_map  = config.get("domain_owners", {})
        domains     = list(owners_map.keys()) if owners_map else load_domains()
        alerts      = _load_alerts()
        slot        = "am" if datetime.now().hour < 12 else "pm"
        today_slot  = f"{date.today()}-{slot}"
        changed     = False

        # Group alerts by owner: {email: [msg, ...]}
        by_owner = {}

        for domain in domains:
            expiry_date, days, error = check_cert(domain)
            if error:
                continue
            key = domain
            msg = _should_alert(domain, days)
            if msg and alerts.get(key) != today_slot:
                owner_email = owners_map.get(domain.lower(), "unknown")
                by_owner.setdefault(owner_email, []).append(
                    f"{msg} _(expires {expiry_date})_"
                )
                alerts[key] = today_slot
                changed = True

        if webhook and by_owner:
            now_str = datetime.now().strftime("%Y-%m-%d %I:%M %p")
            for owner_email, msgs in by_owner.items():
                mention = ""
                if bot_token and owner_email != "unknown":
                    uid = _slack_uid_for_email(owner_email, bot_token)
                    if uid:
                        mention = f" | <@{uid}>"

                text = (
                    f"🔴 *SSL Certificate Alert*{mention}\n\n"
                    + "\n".join(f"  • {m}" for m in msgs)
                    + f"\n\n🤖 _Automated Cert Report | Generated: {now_str}_"
                )
                _post_slack(webhook, text)

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
    domains = list(owners.keys()) if owners else load_domains()
    alerts  = _load_alerts()
    results = []
    for domain in domains:
        expiry_date, days, error = check_cert(domain)
        results.append({
            "domain":  domain,
            "owner":   owners.get(domain.lower(), "—"),
            "expiry":  expiry_date,
            "days":    days,
            "error":   error,
            "alerted": alerts.get(domain),
        })
    return jsonify(results)


@app.route("/save_settings", methods=["POST"])
def save_settings():
    save_config(
        request.form.get("slack_webhook", "").strip(),
        request.form.get("slack_bot_token", "").strip(),
        request.form.get("domain_owners_raw", "").strip(),
    )
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=False, port=5051)
