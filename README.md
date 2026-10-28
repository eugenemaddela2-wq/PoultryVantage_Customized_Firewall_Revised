# PoultryVantage Customized Firewall / IoT Gateway

A Python Flask prototype that sits between an existing ESP32-based farm monitoring source and a cloud endpoint. It does **not** replace the DHT22/MQ-135 sensors, mobile application, or cloud system. It provides application-layer request filtering and device authentication, SQLite buffering, retry/forwarding, security-event logging, a dashboard, and summary reporting.

## Security and reliability changes in this revision

- Conservative default listener (`127.0.0.1`) and loopback-only firewall subnet allowlist; LAN exposure must be enabled deliberately.
- Firewall inspection applies to application routes, including `/approval`; the previous flood test target is no longer exempt.
- `X-Forwarded-For` is ignored unless the immediate peer is listed in `TRUSTED_PROXY_IPS`.
- In-memory sliding-window rate limiting uses monotonic time and prunes old tracking entries.
- Sensitive report, records, backup, logs, retry, and administrative routes have access checks; records/analytics also allow an approved browser session.
- Admin API keys use constant-time comparison; the app refuses to start with missing/placeholder/weak admin or Flask secrets.
- CORS is disabled unless exact trusted origins are configured.
- JSON request body size, ISO-8601 timestamp age, known sensor numeric types, and broad sensor-value bounds are validated.
- Report event fields are HTML-escaped to reduce stored HTML/script injection risk.
- SQLite connections are closed reliably; backups use SQLite's online backup API.
- Forwarded-record rate is labelled accurately and is **not** reported as IP packet delivery ratio (PDR).
- `Flask-Cors` is listed in `requirements.txt`.
- Includes automated security regression tests and a two-laptop LAN measurement client.

## 1. Install and configure (gateway laptop)

Use Python 3.11 or newer. In PowerShell, from this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` before starting. Replace the placeholder `ADMIN_API_KEY`, `FLASK_SECRET_KEY`, and device secret with unique random values. Keep `.env` private; never send it in a source ZIP or commit it to Git. `DEVICE_SECRETS` is JSON mapping device IDs to shared HMAC secrets. For example, use the same device ID and secret in the ESP32/sender and gateway configuration. The app seeds a configured device as approved only when that device is not already in the database; it will not automatically re-approve a revoked device.

Run:

```powershell
python app.py
```

Local dashboard: `http://127.0.0.1:5000/`

## 2. Send a local test payload

In another terminal, with the same environment, run:

```powershell
python test_sender.py
```

`test_sender.py` uses the device secret from `DEVICE_SECRETS`. If the cloud endpoint is blank/unreachable, a valid record should be accepted and buffered rather than forwarded.

## 3. Run the automated tests

```powershell
python -m unittest discover -s tests -v
```

The suite checks HMAC rejection/acceptance, unapproved devices, timestamp and sensor validation, payload-size limit, rate limiting, untrusted forwarded-IP headers, remote backup access control, and report HTML escaping. Tests use a temporary database and do not use the live farm database.

Optional smoke checks against a running local gateway:

```powershell
python penetration_test.py
```

This smoke script does not flood the live server; the rate-limit test is covered by the unit suite.

## 4. Two-laptop LAN test

**Gateway laptop A**

1. Find its private IPv4 address with `ipconfig` (for example `192.168.1.20`).
2. In the gateway `.env`, set `GATEWAY_HOST=0.0.0.0` and change `FIREWALL_ALLOWED_SUBNETS` to the *actual private subnet used by both laptops*. Example only: `127.0.0.1/32,::1/128,192.168.1.0/24`. Do not use `0.0.0.0/0`.
3. Restart the gateway. Allow inbound TCP port 5000 on the private Windows network only if Windows Firewall asks; do not expose it to public networks.
4. Make sure the approved device ID/shared secret is configured in the gateway's `DEVICE_SECRETS` setting.

**Client laptop B**

1. Copy only the source code (not the gateway `.env`, database, logs, or backups) and install the requirements.
2. Create a client-side `.env` containing only these test values:

```text
GATEWAY_URL=http://192.168.1.20:5000/api/data
TEST_DEVICE_ID=CS-ESP32-001
TEST_DEVICE_SECRET=the_same_device_secret_as_gateway
LAN_TEST_COUNT=30
LAN_TEST_INTERVAL_SECONDS=1
```

Replace the example IP and values. Do **not** copy the gateway's admin key or Flask secret to the client laptop.

3. Run `python lan_test_client.py`. It produces timestamped JSON and CSV evidence with HTTP response counts, gateway acceptance counts, client-observed round-trip latency, and accepted-records-per-second.
4. For actual network packet loss, separately run `ping -n 30 192.168.1.20` from laptop B and record the packet-loss percentage shown by Windows. The Python client's response-failure percentage is an **application-level** metric, not IP packet loss. Keep the ping results separate from application RTT/throughput results.

## Important limitations

- The rate limiter is in-memory and resets when the process restarts; it is appropriate for a prototype, not a production-grade distributed firewall.
- HMAC authenticates the payload body, but this revision does not implement a nonce-based replay cache. Timestamp freshness limits stale payloads but does not prevent replay within the accepted time window.
- Latency from the LAN client includes HTTP request/response time. `forwarder.py` measures successful cloud HTTP round-trip latency. Neither metric alone is a pure network-layer latency measurement.
- Throughput and application response failure rate from the LAN script are measured results only for that test run; they are not claims about the network's maximum capacity or packet loss.
- Test on a private trusted LAN and obtain permission before running security tests against any network/device.
