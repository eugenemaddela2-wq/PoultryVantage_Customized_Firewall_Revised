import hashlib
import hmac
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from ipaddress import ip_network
from unittest.mock import patch

_TMP = tempfile.mkdtemp(prefix="poultryvantage-tests-")
os.environ["DB_PATH"] = os.path.join(_TMP, "gateway.db")
os.environ["LOG_PATH"] = os.path.join(_TMP, "gateway.log")
os.environ["BACKUP_DIR"] = os.path.join(_TMP, "backups")
os.environ["FIREWALL_ALLOWED_SUBNETS"] = "127.0.0.1/32,::1/128"
os.environ["ADMIN_API_KEY"] = "test-admin-key-0123456789-strong"
os.environ["FLASK_SECRET_KEY"] = "test-flask-secret-key-0123456789-strong"
os.environ["FIREWALL_RATE_LIMIT"] = "30"
os.environ["FIREWALL_RATE_WINDOW"] = "10"

import app as gateway
from storage import init_db, add_event, register_pending_device, set_device_status, get_device

DEVICE_ID = "TEST-ESP32-001"
DEVICE_SECRET = "test-device-secret-1234567890"

class GatewaySecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        if not get_device(DEVICE_ID):
            register_pending_device(DEVICE_ID)
        set_device_status(DEVICE_ID, "approved", secret_key=DEVICE_SECRET)
        gateway.app.config["TESTING"] = True

    def setUp(self):
        gateway.firewall.request_history.clear()
        gateway.firewall.banned_ips.clear()
        gateway.firewall.rate_limit_requests = 30
        gateway.firewall.allowed_cidrs = [ip_network("127.0.0.1/32"), ip_network("::1/128")]
        self.client = gateway.app.test_client()

    def _signed(self, payload, signature_override=None):
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature = signature_override or hmac.new(DEVICE_SECRET.encode(), raw, hashlib.sha256).hexdigest()
        return self.client.post("/api/data", data=raw, content_type="application/json", headers={"X-Device-ID": DEVICE_ID, "X-Signature": signature})

    def _payload(self, **data):
        return {"timestamp": datetime.now(timezone.utc).isoformat(), "data": {"temperature": 25.0, "humidity": 60.0, "ammonia": 10.0, **data}}

    def test_status_endpoint_is_reachable_on_localhost(self):
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        self.assertIn("gateway", response.get_json())

    def test_forged_hmac_is_rejected(self):
        response = self._signed(self._payload(), "not-a-valid-signature")
        self.assertEqual(response.status_code, 401)

    def test_valid_signed_payload_is_accepted(self):
        with patch("app.forward_payload", return_value=12.5):
            response = self._signed(self._payload())
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(response.get_json()["status"], "forwarded")
        self.assertAlmostEqual(response.get_json()["latency_ms"], 12.5)

    def test_stale_timestamp_is_rejected(self):
        payload = self._payload()
        payload["timestamp"] = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
        response = self._signed(payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn("too old", response.get_json()["error"])

    def test_out_of_range_sensor_value_is_rejected(self):
        response = self._signed(self._payload(humidity=150))
        self.assertEqual(response.status_code, 400)
        self.assertIn("humidity", response.get_json()["error"])

    def test_invalid_timestamp_is_rejected(self):
        payload = self._payload()
        payload["timestamp"] = "not-a-date"
        response = self._signed(payload)
        self.assertEqual(response.status_code, 400)

    def test_empty_sensor_data_is_rejected(self):
        response = self._signed({"timestamp": datetime.now(timezone.utc).isoformat(), "data": {}})
        self.assertEqual(response.status_code, 400)

    def test_oversized_request_is_rejected(self):
        gateway.app.config["MAX_CONTENT_LENGTH"] = 128
        try:
            response = self.client.post("/api/data", data=b"x" * 512, headers={"X-Device-ID": DEVICE_ID, "X-Signature": "x"})
            self.assertEqual(response.status_code, 413)
        finally:
            gateway.app.config["MAX_CONTENT_LENGTH"] = 65536

    def test_unapproved_device_is_rejected(self):
        payload = self._payload()
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        response = self.client.post("/api/data", data=raw, content_type="application/json", headers={"X-Device-ID": "UNREGISTERED-TEST-DEVICE", "X-Signature": "x"})
        self.assertEqual(response.status_code, 403)

    def test_rate_limit_blocks_excess_requests(self):
        gateway.firewall.rate_limit_requests = 3
        results = [self.client.get("/api/status").status_code for _ in range(4)]
        self.assertEqual(results[:3], [200, 200, 200])
        self.assertEqual(results[3], 429)

    def test_forwarded_for_is_ignored_from_untrusted_peer(self):
        with gateway.app.test_request_context("/", environ_base={"REMOTE_ADDR": "127.0.0.1"}, headers={"X-Forwarded-For": "203.0.113.77"}):
            self.assertEqual(gateway.firewall.get_client_ip(), "127.0.0.1")
            self.assertFalse(gateway._is_local_client(), "forwarded requests must not inherit localhost admin bypass")

    def test_backup_list_requires_auth_from_remote_client(self):
        gateway.firewall.allowed_cidrs = [ip_network("0.0.0.0/0"), ip_network("::/0")]
        response = self.client.get("/api/backups", environ_base={"REMOTE_ADDR": "192.0.2.44"})
        self.assertEqual(response.status_code, 401)

    def test_report_escapes_untrusted_event_html(self):
        marker = "<script>alert('xss')</script>"
        add_event("test_event", marker)
        response = self.client.get("/report/summary")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(marker, response.get_data(as_text=True))
        self.assertIn("&lt;script&gt;", response.get_data(as_text=True))

if __name__ == "__main__":
    unittest.main(verbosity=2)
