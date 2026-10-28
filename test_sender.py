"""Send one signed sample payload to a running gateway for manual integration testing."""
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
import requests
from config import DEVICE_SECRETS, HOST, PORT

DEVICE_ID = os.getenv("TEST_DEVICE_ID", "CS-ESP32-001")
SHARED_SECRET = DEVICE_SECRETS.get(DEVICE_ID, "")
GATEWAY_URL = os.getenv("GATEWAY_URL", f"http://127.0.0.1:{PORT}/api/data")

if not isinstance(SHARED_SECRET, str) or len(SHARED_SECRET) < 16:
    raise SystemExit(f"No valid secret configured for {DEVICE_ID}. Add it to DEVICE_SECRETS in .env (at least 16 characters), then restart the gateway.")

payload = {"timestamp": datetime.now(timezone.utc).isoformat(), "data": {"temperature": 30.2, "humidity": 71.5, "ammonia": 12.4, "thi": 78.1}}
raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
signature = hmac.new(SHARED_SECRET.encode("utf-8"), raw, hashlib.sha256).hexdigest()
response = requests.post(GATEWAY_URL, data=raw, headers={"Content-Type": "application/json", "X-Device-ID": DEVICE_ID, "X-Signature": signature}, timeout=10)
print(f"HTTP {response.status_code}")
print(response.text)
