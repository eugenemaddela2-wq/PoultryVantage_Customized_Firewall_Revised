"""Optional continuous sample telemetry generator for local demonstrations."""
import hashlib
import hmac
import json
import os
import random
import time
from datetime import datetime, timezone
import requests
from config import DEVICE_SECRETS, PORT

DEVICE_ID = os.getenv("TEST_DEVICE_ID", "CS-ESP32-001")
SHARED_SECRET = DEVICE_SECRETS.get(DEVICE_ID, "")
GATEWAY_URL = os.getenv("GATEWAY_URL", f"http://127.0.0.1:{PORT}/api/data")
if not isinstance(SHARED_SECRET, str) or len(SHARED_SECRET) < 16:
    raise SystemExit(f"No valid secret configured for {DEVICE_ID}. Configure DEVICE_SECRETS in .env and restart the gateway.")

temp, humidity, ammonia = 24.5, 62.0, 12.0
counter = 1
print(f"Sending simulated telemetry for {DEVICE_ID} to {GATEWAY_URL}; press Ctrl+C to stop.")
while True:
    temp = max(18.0, min(35.0, temp + random.uniform(-0.4, 0.4)))
    humidity = max(40.0, min(85.0, humidity + random.uniform(-0.8, 0.8)))
    ammonia = max(5.0, min(32.0, ammonia + random.uniform(-0.3, 0.3)))
    thi = (0.8 * temp) + ((humidity / 100.0) * (temp - 14.4)) + 46.4
    payload = {"timestamp": datetime.now(timezone.utc).isoformat(), "data": {"temperature": round(temp, 1), "humidity": round(humidity, 1), "ammonia": round(ammonia, 1), "thi": round(thi, 1)}}
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(SHARED_SECRET.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    try:
        start = time.perf_counter()
        response = requests.post(GATEWAY_URL, data=raw, headers={"Content-Type": "application/json", "X-Device-ID": DEVICE_ID, "X-Signature": signature}, timeout=5)
        elapsed = (time.perf_counter() - start) * 1000
        print(f"[{counter}] HTTP {response.status_code}; client round-trip={elapsed:.1f} ms; {response.text[:180]}")
    except requests.RequestException as exc:
        print(f"Send failed: {exc}")
    counter += 1
    time.sleep(3)
