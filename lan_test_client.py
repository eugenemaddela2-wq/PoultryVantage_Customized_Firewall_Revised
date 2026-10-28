"""Run an application-level gateway test from a second laptop on the same LAN.

Configure only these client-side environment variables in the client laptop's .env:
  GATEWAY_URL=http://<gateway-lan-ip>:5000/api/data
  TEST_DEVICE_ID=CS-ESP32-001
  TEST_DEVICE_SECRET=<the same device secret configured on the gateway>
"""
import csv
import hashlib
import hmac
import json
import os
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv
import requests

load_dotenv()
URL = os.getenv("GATEWAY_URL", "").strip()
DEVICE_ID = os.getenv("TEST_DEVICE_ID", "CS-ESP32-001").strip()
SECRET = os.getenv("TEST_DEVICE_SECRET", "")
COUNT = max(1, int(os.getenv("LAN_TEST_COUNT", "30")))
INTERVAL = max(0.0, float(os.getenv("LAN_TEST_INTERVAL_SECONDS", "1")))

if not URL.startswith("http://") and not URL.startswith("https://"):
    raise SystemExit("Set GATEWAY_URL in the client laptop's .env, e.g. http://192.168.1.20:5000/api/data")
if len(SECRET) < 16 or SECRET.startswith("REPLACE_"):
    raise SystemExit("Set TEST_DEVICE_SECRET to the approved device's shared secret (16+ characters). Do not copy the admin key.")

results = []
start_all = time.perf_counter()
for index in range(1, COUNT + 1):
    payload = {"timestamp": datetime.now(timezone.utc).isoformat(), "data": {"temperature": 25.0 + (index % 5) / 10, "humidity": 60.0, "ammonia": 10.0, "thi": 72.0}}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(SECRET.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    started = time.perf_counter()
    try:
        response = requests.post(URL, data=raw, headers={"Content-Type": "application/json", "X-Device-ID": DEVICE_ID, "X-Signature": signature}, timeout=10)
        rtt_ms = (time.perf_counter() - started) * 1000
        accepted = response.status_code in (200, 202)
        try:
            body = response.json()
        except ValueError:
            body = {"response_excerpt": response.text[:160]}
        results.append({"sequence": index, "http_status": response.status_code, "accepted": accepted, "round_trip_ms": round(rtt_ms, 3), "gateway_status": body.get("status", ""), "record_id": body.get("record_id", ""), "error": body.get("error", "")})
        print(f"{index:03}/{COUNT}: HTTP {response.status_code}, accepted={accepted}, RTT={rtt_ms:.1f} ms, gateway={body.get('status', 'n/a')}")
    except requests.RequestException as exc:
        rtt_ms = (time.perf_counter() - started) * 1000
        results.append({"sequence": index, "http_status": "NO_RESPONSE", "accepted": False, "round_trip_ms": round(rtt_ms, 3), "gateway_status": "", "record_id": "", "error": str(exc)[:200]})
        print(f"{index:03}/{COUNT}: NO RESPONSE ({exc})")
    if index < COUNT and INTERVAL:
        time.sleep(INTERVAL)

duration = time.perf_counter() - start_all
accepted_count = sum(bool(row["accepted"]) for row in results)
received_count = sum(row["http_status"] != "NO_RESPONSE" for row in results)
latencies = [row["round_trip_ms"] for row in results if row["http_status"] != "NO_RESPONSE"]
summary = {
    "target_url": URL,
    "device_id": DEVICE_ID,
    "test_started_utc": datetime.now(timezone.utc).isoformat(),
    "requests_sent": COUNT,
    "responses_received": received_count,
    "records_accepted_by_gateway": accepted_count,
    "application_response_failure_rate_percent": round((COUNT - received_count) / COUNT * 100, 2),
    "gateway_rejection_rate_percent": round((received_count - accepted_count) / COUNT * 100, 2),
    "average_round_trip_ms": round(statistics.mean(latencies), 3) if latencies else None,
    "median_round_trip_ms": round(statistics.median(latencies), 3) if latencies else None,
    "minimum_round_trip_ms": round(min(latencies), 3) if latencies else None,
    "maximum_round_trip_ms": round(max(latencies), 3) if latencies else None,
    "accepted_records_per_second_over_test_duration": round(accepted_count / duration, 3) if duration > 0 else None,
    "duration_seconds": round(duration, 3),
    "note": "These are application-level HTTP response/acceptance measurements, not IP packet-loss measurements. Use ping/pathping separately for network packet loss."
}
stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
json_path = Path(f"lan_test_results_{stamp}.json")
csv_path = Path(f"lan_test_results_{stamp}.csv")
json_path.write_text(json.dumps({"summary": summary, "requests": results}, indent=2), encoding="utf-8")
with csv_path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(results[0].keys()))
    writer.writeheader()
    writer.writerows(results)
print("\nSUMMARY")
print(json.dumps(summary, indent=2))
print(f"Saved evidence: {json_path} and {csv_path}")
