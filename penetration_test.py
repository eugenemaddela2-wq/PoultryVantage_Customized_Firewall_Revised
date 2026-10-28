"""Non-destructive local security smoke checks for a running gateway.
Rate-limit behavior is tested deterministically in tests/test_gateway_security.py;
this script intentionally does not flood the live server or temporarily ban localhost.
"""
import os
import requests

TARGET_URL = os.getenv("GATEWAY_BASE_URL", "http://127.0.0.1:5000").rstrip("/")
DEVICE_URL = f"{TARGET_URL}/api/data"
results = []

def check(name, passed, detail):
    results.append(bool(passed))
    print(f"{'PASS' if passed else 'FAIL'} | {name} | {detail}")

try:
    response = requests.get(f"{TARGET_URL}/api/status", timeout=5)
    check("Gateway status reachable", response.status_code == 200, f"HTTP {response.status_code}")
except requests.RequestException as exc:
    raise SystemExit(f"Gateway is not reachable at {TARGET_URL}: {exc}")

try:
    response = requests.get(f"{TARGET_URL}/api/admin/devices", headers={"X-Admin-Key": "deliberately-wrong-test-key"}, timeout=5)
    check("Wrong admin key rejected", response.status_code == 401, f"HTTP {response.status_code}")
except requests.RequestException as exc:
    check("Wrong admin key rejected", False, str(exc))

try:
    response = requests.post(DEVICE_URL, json={"timestamp": "not-a-date", "data": {"temperature": 25}}, headers={"X-Device-ID": "UNREGISTERED-SMOKE-TEST", "X-Signature": "invalid"}, timeout=5)
    check("Unregistered device rejected", response.status_code == 403, f"HTTP {response.status_code}")
except requests.RequestException as exc:
    check("Unregistered device rejected", False, str(exc))

passed = sum(results)
print(f"\nSmoke checks passed: {passed}/{len(results)} ({passed / len(results) * 100:.1f}%)")
raise SystemExit(0 if passed == len(results) else 1)
