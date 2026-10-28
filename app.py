import json
import math
import html
import logging
import os
import secrets
import threading
import time
import sqlite3
from pathlib import Path
from flask_cors import CORS
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request, render_template, render_template_string, send_from_directory, make_response

from config import (
    HOST, PORT, DEVICE_SECRETS, LOG_PATH, RETRY_INTERVAL_SECONDS,
    MAX_RETRY_ATTEMPTS, CLOUD_ENDPOINT, BACKUP_DIR, BACKUP_INTERVAL_SECONDS, FIREWALL_ALLOWED_SUBNETS, FIREWALL_BLOCKED_IPS, FIREWALL_RATE_LIMIT,
    FIREWALL_RATE_WINDOW, FIREWALL_BAN_DURATION, FLASK_SECRET_KEY, TRUSTED_CORS_ORIGINS, TRUSTED_PROXY_IPS, MAX_PAYLOAD_BYTES, MAX_TIMESTAMP_AGE_SECONDS
)
from config import ADMIN_API_KEY
from notifier import send_admin_alert
from storage import get_device, register_pending_device, set_device_status, list_devices
from firewall import GatewayFirewall
from forwarder import forward_payload
from security import verify_signature
from storage import (
    init_db, add_record, mark_forwarded, mark_failed, get_pending,
    get_recent_records, add_event, get_recent_events, counts, backup_database, get_performance_stats, request_browser_access, get_browser_status,
    list_browser_requests, grant_browser_access, revoke_browser_access, update_browser_heartbeat, ban_ip_address, is_ip_permanently_banned, unban_ip_address
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_PAYLOAD_BYTES
if FLASK_SECRET_KEY:
    app.secret_key = FLASK_SECRET_KEY
if TRUSTED_CORS_ORIGINS:
    CORS(app, origins=TRUSTED_CORS_ORIGINS, supports_credentials=False)

Path(LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
)
logger = logging.getLogger("gateway")

firewall = GatewayFirewall(
    allowed_cidrs=FIREWALL_ALLOWED_SUBNETS,
    blocked_ips=FIREWALL_BLOCKED_IPS,
    rate_limit_requests=FIREWALL_RATE_LIMIT,
    rate_limit_window_seconds=FIREWALL_RATE_WINDOW,
    ban_duration_seconds=FIREWALL_BAN_DURATION,
    trusted_proxy_ips=TRUSTED_PROXY_IPS
)


@app.post("/api/admin/revoke_browser")
def admin_revoke_browser():
    if not _require_admin_or_local():
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json() or {}
    token = data.get("session_token")
    if not token:
        return jsonify({"error": "session_token required"}), 400
        
    revoke_browser_access(token)
    add_event("admin_revoke", f"Revoked dashboard access for Pairing ID: {token}")
    return jsonify({"ok": True, "message": f"Device {token} disconnected."})

@app.before_request
def enforce_firewall():
    # All real routes, including approval/report routes, pass through the filter.
    if request.path.startswith("/static/") or request.method == "OPTIONS":
        return None
    client_ip = firewall.get_client_ip()
    if is_ip_permanently_banned(client_ip):
        add_event("firewall_blocked", f"{client_ip} - persistent IP ban")
        return jsonify({"ok": False, "error": "Firewall: client IP is permanently blocked."}), 403
    passed, error_msg, status_code = firewall.inspect_request()
    if not passed:
        logger.warning("Firewall blocked request from %s: %s", client_ip, error_msg)
        add_event("firewall_blocked", f"{client_ip} - {error_msg}")
        return jsonify({"ok": False, "error": error_msg}), status_code

def _is_local_client():
    # Do not treat a request arriving through a local reverse proxy/tunnel as a local user.
    if request.headers.get("X-Forwarded-For") or request.headers.get("X-Original-Host"):
        return False
    if "ngrok" in request.host.lower() or "ngrok" in request.headers.get("User-Agent", "").lower():
        return False
    return request.remote_addr in {"127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"}

def check_admin_auth():
    supplied = request.headers.get("X-Admin-Key", "")
    return bool(ADMIN_API_KEY and secrets.compare_digest(supplied, ADMIN_API_KEY))

def _require_admin_or_local():
    return _is_local_client() or check_admin_auth()

def _require_admin_or_approved_browser():
    token = request.cookies.get("gateway_device_token") or request.cookies.get("pv_pairing_token")
    return _require_admin_or_local() or bool(token and get_browser_status(token) == "approved")

def validate_payload(payload):
    if not isinstance(payload, dict):
        return False, "JSON object required"
    missing = [key for key in ("timestamp", "data") if key not in payload]
    if missing:
        return False, f"Missing fields: {', '.join(missing)}"
    if not isinstance(payload["data"], dict):
        return False, "data must be an object"
    if not any(field in payload["data"] for field in ("temperature", "humidity", "ammonia", "thi")):
        return False, "data must contain at least one recognized sensor measurement"
    timestamp = payload.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.strip():
        return False, "timestamp must be an ISO-8601 string"
    try:
        parsed = datetime.fromisoformat(timestamp.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds()
        if age > MAX_TIMESTAMP_AGE_SECONDS:
            return False, f"timestamp is too old (maximum age {MAX_TIMESTAMP_AGE_SECONDS}s)"
        if age < -60:
            return False, "timestamp is too far in the future"
    except (ValueError, OverflowError):
        return False, "timestamp must be a valid ISO-8601 date/time"
    limits = {"temperature": (-50.0, 100.0), "humidity": (0.0, 100.0), "ammonia": (0.0, 10000.0), "thi": (-50.0, 150.0)}
    for field, (minimum, maximum) in limits.items():
        if field not in payload["data"]:
            continue
        value = payload["data"][field]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            return False, f"data.{field} must be a finite number"
        try:
            numeric_value = float(value)
        except (OverflowError, ValueError):
            return False, f"data.{field} must be a finite number"
        if not math.isfinite(numeric_value):
            return False, f"data.{field} must be a finite number"
        if not minimum <= numeric_value <= maximum:
            return False, f"data.{field} must be between {minimum:g} and {maximum:g}"
    return True, None


def try_forward(record_id, payload_text):
    try:
        latency_ms = forward_payload(payload_text)
        mark_forwarded(record_id, latency_ms)
        add_event("forward_success", f"Record {record_id} forwarded in {latency_ms:.1f} ms")
        logger.info("Record %s forwarded", record_id)
        return True, latency_ms
    except Exception as exc:
        mark_failed(record_id, exc)
        add_event("forward_failed", f"Record {record_id}: {exc}")
        logger.warning("Forward failed for record %s: %s", record_id, exc)
        return False, None


def retry_worker():
    while True:
        try:
            for row in get_pending(limit=100):
                if row["attempts"] >= MAX_RETRY_ATTEMPTS:
                    continue
                try_forward(row["id"], row["payload"])
        except Exception as exc:
            logger.exception("Retry worker error: %s", exc)
        time.sleep(RETRY_INTERVAL_SECONDS)


def backup_worker():
    while True:
        time.sleep(BACKUP_INTERVAL_SECONDS)
        try:
            path = backup_database()
            add_event("automated_backup", f"Automated backup generated: {path}")
            logger.info("Automated backup created at %s", path)
        except Exception as exc:
            logger.error("Automated backup error: %s", exc)




PAIRING_SCREEN_HTML = """
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gateway Access - PoultryVantage</title>
  <style>
    :root {
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --border: #e2e8f0;
      --text: #1e293b;
      --text-muted: #64748b;
      --primary: #0284c7;
      --danger: #dc2626;
    }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; padding: 16px; }
    .card { background: var(--card-bg); border: 1px solid var(--border); padding: 32px 24px; border-radius: 8px; max-width: 420px; width: 100%; text-align: center; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
    .spinner { border: 3px solid #e2e8f0; border-top: 3px solid var(--primary); border-radius: 50%; width: 36px; height: 36px; animation: spin 1s linear infinite; margin: 20px auto; }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    .token { font-family: monospace; background: #f1f5f9; padding: 4px 8px; border-radius: 4px; color: var(--primary); font-weight: 700; font-size: 1rem; border: 1px solid var(--border); }
    .ban-card { border-color: #fecaca; }
    .ban-title { color: var(--danger); font-size: 1.25rem; font-weight: 700; margin-bottom: 8px; }
  </style>
</head>
<body>
  {% if is_banned %}
  <div class="card ban-card">
    <div style="font-size: 44px; margin-bottom: 8px;">⛔</div>
    <div class="ban-title">YOU ARE BANNED</div>
    <p style="color: var(--text-muted); font-size: 14px; line-height: 1.5;">Your IP address (<strong>{{ client_ip }}</strong>) has been permanently blocked by the PoultryVantage firewall administrator.</p>
  </div>
  {% else %}
  <div class="card">
    <div style="font-size: 38px; margin-bottom: 8px;">📶</div>
    <h2 style="font-size: 1.2rem; margin: 0 0 6px 0; color: #0f172a;">Access Request Sent</h2>
    <p style="color: var(--text-muted); font-size: 13px; margin: 0;">Waiting for the administrator to approve this device...</p>
    <div class="spinner"></div>
    <p style="font-size: 13px; color: var(--text-muted); margin: 0;">Device Pairing ID: <span class="token">{{ token }}</span></p>
  </div>
  <script>
    setInterval(async () => {
      try {
        const res = await fetch('/api/pairing/status');
        const data = await res.json();
        if (data.status === 'approved') {
          window.location.reload();
        } else if (data.status === 'banned') {
          window.location.reload();
        }
      } catch (e) {}
    }, 2000);
  </script>
  {% endif %}
</body>
</html>
"""  


@app.get("/report/summary")
def generate_summary_report():
    """Generates a printable summary report for local/admin/approved users."""
    if not _require_admin_or_approved_browser():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    stats = get_performance_stats()
    records = get_recent_records(limit=100)
    events = get_recent_events(limit=50)

    # Compute sensor averages from real database records
    valid_temps, valid_hums, valid_nh3s = [], [], []
    for r in records:
        try:
            d = json.loads(r["payload"]).get("data", {})
            if "temperature" in d: valid_temps.append(float(d["temperature"]))
            if "humidity" in d: valid_hums.append(float(d["humidity"]))
            if "ammonia" in d: valid_nh3s.append(float(d["ammonia"]))
        except Exception:
            continue

    avg_t = round(sum(valid_temps) / len(valid_temps), 2) if valid_temps else 0.0
    avg_h = round(sum(valid_hums) / len(valid_hums), 2) if valid_hums else 0.0
    avg_n = round(sum(valid_nh3s) / len(valid_nh3s), 2) if valid_nh3s else 0.0

    report_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>PoultryVantage Gateway Summary Report</title>
      <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; padding: 40px; color: #1e293b; }}
        h1 {{ border-bottom: 2px solid #0284c7; padding-bottom: 8px; color: #0369a1; }}
        h2 {{ color: #334155; margin-top: 25px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; margin-bottom: 25px; }}
        th, td {{ border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; font-size: 13px; }}
        th {{ background-color: #f1f5f9; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }}
        .badge-ok {{ background: #dcfce7; color: #15803d; }}
        @media print {{
          button {{ display: none; }}
          body {{ padding: 0; }}
        }}
      </style>
    </head>
    <body>
      <button onclick="window.print()" style="float: right; padding: 8px 16px; background: #0284c7; color: white; border: none; border-radius: 4px; cursor: pointer;">
        Save as PDF / Print
      </button>
      <h1>PoultryVantage Gateway Executive Summary Report</h1>
      <p><strong>Generated Date:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
      <p><strong>Project:</strong> Customized Firewall for PoultryVantage Farm Data Monitoring</p>

      <h2>1. Network Performance Parameters (Objective #1)</h2>
      <table>
        <tr><th>Metric Parameter</th><th>Observed Value</th><th>Status / Standard</th></tr>
        <tr><td>Transmission Latency</td><td>{stats.get('avg_latency_ms', 0)} ms</td><td>Nominal (&lt; 1500 ms)</td></tr>
        <tr><td>Forwarded Record Rate (not packet delivery ratio)</td><td>{stats.get('forwarded_record_rate', 0)}%</td><td>Forwarded records / stored records</td></tr>
        <tr><td>Offline Buffered Records</td><td>{stats.get('buffered_count', 0)} frames</td><td>Local SQLite Buffer</td></tr>
      </table>

      <h2>2. Environmental Telemetry Summary (CS Sensor Inputs)</h2>
      <table>
        <tr><th>Parameter</th><th>Average Reading</th><th>Target Nominal Range</th></tr>
        <tr><td>Temperature</td><td>{avg_t} °C</td><td>18.0 °C - 26.0 °C</td></tr>
        <tr><td>Relative Humidity</td><td>{avg_h} %</td><td>50.0% - 70.0%</td></tr>
        <tr><td>Ammonia Level (NH3)</td><td>{avg_n} ppm</td><td>&lt; 20.0 ppm</td></tr>
      </table>

      <h2>3. Security & Firewall Audit Trail (Supporting Evidence)</h2>
      <table>
        <tr><th>Timestamp</th><th>Event Type</th><th>Details</th></tr>
        {''.join(f"<tr><td>{html.escape(str(e.get('created_at', '')))}</td><td>{html.escape(str(e.get('event_type', '')))}</td><td>{html.escape(str(e.get('message', '')))}</td></tr>" for e in events[:10])}
      </table>
    </body>
    </html>
    """
    return report_html

# --- API ROUTES ---
@app.get("/")
def index_page():
    try:
        is_proxied = bool(
            request.headers.get("X-Forwarded-For") 
            or "ngrok" in request.headers.get("User-Agent", "").lower() 
            or request.headers.get("X-Original-Host")
            or "ngrok" in request.host.lower()
        )

        client_ip = firewall.get_client_ip()

        user_agent = request.headers.get("User-Agent", "Unknown Device")

        # 1. Check if IP is permanently banned
        if is_ip_permanently_banned(client_ip):
            html = render_template_string(PAIRING_SCREEN_HTML, is_banned=True, client_ip=client_ip, token="")
            return make_response(html, 403)

        # 2. Host PC bypass for direct localhost
        is_direct_host = request.remote_addr in ["127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"] and not is_proxied
        if is_direct_host:
            return render_template("index.html")

        token = request.cookies.get("gateway_device_token") or request.cookies.get("pv_pairing_token")
        status = get_browser_status(token) if token else None

        if token and status == "approved":
            return render_template("index.html")

        if not token or status not in ["pending", "approved"]:
            token = secrets.token_hex(6)
            request_browser_access(token, client_ip, user_agent)
            print(f">>> [APPROVAL NEEDED] Device {token} from IP {client_ip} registered for approval!")

        html = render_template_string(PAIRING_SCREEN_HTML, is_banned=False, token=token, client_ip=client_ip)
        resp = make_response(html)
        resp.set_cookie("gateway_device_token", token, max_age=86400 * 30, samesite="Lax")
        resp.set_cookie("pv_pairing_token", token, max_age=86400 * 30, samesite="Lax")
        return resp

    except Exception as e:
        logger.error("Error in index_page: %s", e)
        return render_template_string(PAIRING_SCREEN_HTML, is_banned=False, token="Error", client_ip="Unknown")



@app.post("/api/admin/ban_ip")
def admin_ban_ip():
    if not _require_admin_or_local():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    ip = data.get("ip_address")
    if not ip:
        return jsonify({"error": "ip_address required"}), 400

    ban_ip_address(ip)
    add_event("admin_ban", f"Firewall permanently banned IP: {ip}")
    return jsonify({"ok": True, "message": f"IP {ip} has been banned."})

@app.post("/api/admin/unban_ip")
def admin_unban_ip():
    if not _require_admin_or_local():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json() or {}
    ip = data.get("ip_address")
    if not ip:
        return jsonify({"error": "ip_address required"}), 400

    unban_ip_address(ip)
    add_event("admin_unban", f"Firewall unbanned IP: {ip}")
    return jsonify({"ok": True, "message": f"IP {ip} unbanned."})


@app.get("/api/pairing/status")
def pairing_status():
    token = request.cookies.get("gateway_device_token") or request.cookies.get("pv_pairing_token")
    if not token:
        return jsonify({"status": "unknown"})
    return jsonify({"status": get_browser_status(token), "token": token})

@app.get("/api/admin/browser_requests")
def admin_browser_requests():
    # Only allow localhost or valid admin key
    if not _require_admin_or_local():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(list_browser_requests())


@app.post("/api/admin/grant_browser")
def admin_grant_browser():
    if not _require_admin_or_local():
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json() or {}
    token = data.get("session_token")
    if not token:
        return jsonify({"error": "session_token required"}), 400
        
    grant_browser_access(token)
    add_event("admin_grant", f"Granted dashboard access to Pairing ID: {token}")
    return jsonify({"ok": True, "message": f"Device {token} granted access."})

@app.get("/approval")
def approval_page():
    client_ip = request.remote_addr or "127.0.0.1"

    # Strict Master Admin Guard: Only allow the host PC running the gateway
    if not _is_local_client():
        return (
            "<h2 style='color:#ef4444; font-family:sans-serif; text-align:center; margin-top:50px;'>"
            "⛔ 403 Forbidden: Master Admin Access Only.<br>"
            "<small style='color:#64748b; font-size:14px;'>Approvals can only be managed directly on the gateway host machine.</small>"
            "</h2>",
            403
        )

    return render_template("approval.html")




@app.get("/api/recommendations")
def recommendations():
    stats = get_performance_stats()
    items = []
    
    if stats["avg_latency_ms"] > 1500:
        items.append({
            "severity": "WARNING",
            "metric": "Latency",
            "issue": f"High average cloud transmission latency ({stats['avg_latency_ms']} ms).",
            "recommendation": "Check gateway internet uplink or packet payloads."
        })
    else:
        items.append({
            "severity": "NORMAL",
            "metric": "Latency",
            "issue": "Latency within nominal parameters.",
            "recommendation": "Current network throughput is sufficient."
        })

    if stats["forwarded_record_rate"] < 95.0:
        items.append({
            "severity": "CRITICAL",
            "metric": "Forwarded Record Rate",
            "issue": f"Delivery rate is {stats['forwarded_record_rate']}%, below target threshold.",
            "recommendation": "Inspect gateway antenna and Wi-Fi coverage."
        })
    else:
        items.append({
            "severity": "NORMAL",
            "metric": "Forwarded Record Rate",
            "issue": f"Delivery rate is healthy at {stats['forwarded_record_rate']}%.",
            "recommendation": "Continue standard operations."
        })

    if stats["buffered_count"] > 20:
        items.append({
            "severity": "WARNING",
            "metric": "Queue Size",
            "issue": f"{stats['buffered_count']} records pending sync in local buffer.",
            "recommendation": "Trigger manual synchronization (/api/retry)."
        })

    return jsonify({
        "metrics": stats,
        "recommendations": items
    })  


@app.post("/api/data")
def receive_data():
    device_id = request.headers.get("X-Device-ID", "").strip()
    signature = request.headers.get("X-Signature", "").strip()
    raw_body = request.get_data(cache=True)
    client_ip = firewall.get_client_ip()
    if len(raw_body) > MAX_PAYLOAD_BYTES:
        return jsonify({"ok": False, "error": "payload exceeds configured size limit"}), 413

    if not device_id:
        return jsonify({"ok": False, "error": "Missing X-Device-ID header"}), 400
    if len(device_id) > 100:
        return jsonify({"ok": False, "error": "X-Device-ID must be at most 100 characters"}), 400

    # 1. Lookup Device Access Status
    device_record = get_device(device_id)

    # 2. Case: Completely unknown device requesting access for the first time
    if not device_record:
        register_pending_device(device_id)
        send_admin_alert(device_id, client_ip, reason="New unapproved device requesting access")
        add_event("auth_pending", f"Device {device_id} from {client_ip} registered for approval")
        return jsonify({
            "ok": False,
            "error": "Device access is pending administrator approval."
        }), 403

    # 3. Case: Device is known but not yet approved
    if device_record["status"] != "approved":
        send_admin_alert(device_id, client_ip, reason=f"Access blocked (status: {device_record['status']})")
        return jsonify({
            "ok": False, 
            "error": f"Device is currently {device_record['status']}. Administrator approval required."
        }), 403

    # 4. Case: Device is approved -> Verify HMAC signature
    shared_secret = device_record["secret_key"]
    if not verify_signature(shared_secret, raw_body, signature):
        add_event("auth_rejected", f"Invalid signature for approved device {device_id}")
        return jsonify({"ok": False, "error": "invalid signature"}), 401

    # 5. Process valid payload
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "error": "invalid JSON"}), 400

    valid, error = validate_payload(payload)
    if not valid:
        return jsonify({"ok": False, "error": error}), 400

    payload_text = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    record_id = add_record(device_id, payload_text)
    add_event("data_received", f"Record {record_id} accepted from {device_id}")

    forwarded, latency_ms = try_forward(record_id, payload_text)
    return jsonify({
        "ok": True,
        "record_id": record_id,
        "device_id": device_id,
        "status": "forwarded" if forwarded else "buffered",
        "latency_ms": latency_ms,
    }), 200 if forwarded else 202


@app.get("/api/status")
def status():
    return jsonify({
        "gateway": "online",
        "cloud_endpoint_configured": bool(CLOUD_ENDPOINT),
        "records": counts(),
        "authorized_device_count": len(list_devices()),
    })

@app.get("/api/analytics")
def get_analytics():
    if not _require_admin_or_approved_browser():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    range_type = request.args.get("range", "daily")
    limit_map = {"daily": 24, "weekly": 168, "monthly": 720}
    max_records = limit_map.get(range_type, 100)

    raw_records = get_recent_records(limit=max_records)
    time_series = []
    comfort_stats = {"Comfortable": 0, "Heat Stress Risk": 0, "High Ammonia Risk": 0}
    
    total_temp, total_hum, total_nh3, count = 0.0, 0.0, 0.0, 0

    for r in reversed(raw_records):
        try:
            payload = json.loads(r["payload"])
            data = payload.get("data", {})
            temp = float(data.get("temperature", 0))
            hum = float(data.get("humidity", 0))
            nh3 = float(data.get("ammonia", 0))
            thi = float(data.get("thi", 0))

            total_temp += temp
            total_hum += hum
            total_nh3 += nh3
            count += 1

            if nh3 > 25:
                comfort_stats["High Ammonia Risk"] += 1
            elif thi > 78 or temp > 32:
                comfort_stats["Heat Stress Risk"] += 1
            else:
                comfort_stats["Comfortable"] += 1

            time_series.append({
                "time": r["received_at"][11:16],
                "temperature": round(temp, 1),
                "humidity": round(hum, 1),
                "ammonia": round(nh3, 1),
                "thi": round(thi, 1)
            })
        except Exception:
            continue

    return jsonify({
        "time_series": time_series,
        "distribution": comfort_stats,
        "summary": {
            "avg_temp": round(total_temp / count, 1) if count else 0,
            "avg_hum": round(total_hum / count, 1) if count else 0,
            "avg_nh3": round(total_nh3 / count, 1) if count else 0,
            "sample_count": count
        }
    })


@app.get("/api/records")
def records():
    if not _require_admin_or_approved_browser():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except ValueError:
        return jsonify({"ok": False, "error": "limit must be an integer"}), 400
    return jsonify(get_recent_records(limit))



@app.get("/api/backups")
def list_backups():
    if not _require_admin_or_local():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    try:
        backup_path = Path(BACKUP_DIR)
        if not backup_path.exists():
            return jsonify([])
        files = [f.name for f in backup_path.glob("*.db")]
        return jsonify(files)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.get("/api/backups/download/<filename>")
def download_backup(filename):
    if not _require_admin_or_local():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    if not filename.endswith(".db") or Path(filename).name != filename:
        return jsonify({"ok": False, "error": "Invalid backup filename"}), 400
    try:
        return send_from_directory(BACKUP_DIR, filename, as_attachment=True)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 404
    

@app.get("/api/logs")
def logs():
    if not _require_admin_or_local():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 500))
    except ValueError:
        return jsonify({"ok": False, "error": "limit must be an integer"}), 400
    return jsonify(get_recent_events(limit))


@app.post("/api/retry")
def retry_now():
    if not _require_admin_or_local():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    attempted = 0
    forwarded = 0
    for row in get_pending(limit=100):
        if row["attempts"] >= MAX_RETRY_ATTEMPTS:
            continue
        attempted += 1
        ok, _ = try_forward(row["id"], row["payload"])
        forwarded += int(ok)
    return jsonify({"attempted": attempted, "forwarded": forwarded})


@app.post("/api/backup")
def backup():
    if not _require_admin_or_local():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    try:
        path = backup_database()
        add_event("backup_created", path)
        return jsonify({"ok": True, "backup": path})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.get("/api/admin/devices")
def admin_list_devices():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return jsonify(list_devices())

@app.post("/api/admin/approve")
def admin_approve_device():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    
    data = request.get_json() or {}
    device_id = data.get("device_id")
    secret_key = data.get("secret_key")  # Pre-shared key for HMAC signature verification

    if not device_id or not secret_key:
        return jsonify({"ok": False, "error": "device_id and secret_key are required"}), 400

    set_device_status(device_id, "approved", secret_key=secret_key)
    add_event("admin_action", f"Device {device_id} was approved by administrator.")
    return jsonify({"ok": True, "message": f"Device {device_id} approved successfully."})

@app.post("/api/admin/revoke")
def admin_revoke_device():
    if not check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    
    data = request.get_json() or {}
    device_id = data.get("device_id")
    if not device_id:
        return jsonify({"ok": False, "error": "device_id required"}), 400

    set_device_status(device_id, "revoked")
    add_event("admin_action", f"Device {device_id} was revoked by administrator.")
    return jsonify({"ok": True, "message": f"Device {device_id} revoked."})

@app.post("/api/session/heartbeat")
def session_heartbeat():
    """Keeps live duration and presence active for connected browser clients."""
    token = request.cookies.get("gateway_device_token") or request.cookies.get("pv_pairing_token")
    if token:
        update_browser_heartbeat(token)
        return jsonify({"ok": True}), 200
    return jsonify({"error": "No token"}), 400

    


# --- SERVER ENTRYPOINT ---

if __name__ == "__main__":
    if not FLASK_SECRET_KEY or len(FLASK_SECRET_KEY) < 32 or FLASK_SECRET_KEY.startswith("REPLACE_"):
        raise RuntimeError("Set FLASK_SECRET_KEY to a unique random secret of at least 32 characters in .env before starting the gateway.")
    if not ADMIN_API_KEY or len(ADMIN_API_KEY) < 24 or ADMIN_API_KEY.startswith("REPLACE_"):
        raise RuntimeError("Set ADMIN_API_KEY to a unique random secret of at least 24 characters in .env before starting the gateway.")
    init_db()
    for configured_id, configured_secret in DEVICE_SECRETS.items():
        if isinstance(configured_id, str) and configured_id.strip() and isinstance(configured_secret, str) and len(configured_secret) >= 16 and not configured_secret.startswith("REPLACE_"):
            if not get_device(configured_id):
                register_pending_device(configured_id)
                set_device_status(configured_id, "approved", secret_key=configured_secret)
    add_event("gateway_started", f"Gateway started on {HOST}:{PORT}")
    threading.Thread(target=retry_worker, daemon=True).start()
    threading.Thread(target=backup_worker, daemon=True).start()
    app.run(host=HOST, port=PORT, debug=False)