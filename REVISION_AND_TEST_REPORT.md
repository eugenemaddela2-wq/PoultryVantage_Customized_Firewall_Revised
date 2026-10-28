# Revision and Test Report

## Revision scope

This is a source-only security and reliability revision of the existing Flask gateway. The dashboard, device approval workflow, HMAC-SHA256 request authentication, SQLite telemetry storage, buffering/retry, mock cloud, and report remain part of the project. No physical firewall appliance, OS-level packet filtering, or integration with a real farm/cloud service is claimed.

## Audit findings addressed

| Previous finding | Revision |
|---|---|
| Allow-all subnet `0.0.0.0/0` | Default firewall allowlist is loopback only; LAN use requires a deliberate private subnet configuration. |
| Service listening on every interface by default | Default `GATEWAY_HOST=127.0.0.1`; use `0.0.0.0` only for private-LAN testing. |
| Sensitive report/records/backup/log/retry endpoints lacked adequate access checks | Added local/admin/approved-browser checks based on route sensitivity. Remote backup and log access requires admin authentication. |
| `X-Forwarded-For` trusted from any sender | Forwarded IP is honored only when the immediate peer is explicitly configured as a trusted proxy; proxy/tunnel requests do not inherit the localhost admin bypass. |
| Report inserted event fields into HTML | Event timestamp, type, and message are HTML-escaped. |
| Payload validation only checked object shape | Added body-size cap, ISO-8601 timestamp validation/freshness, required recognized sensor data, numeric/finiteness checks, and broad sensor bounds. |
| Rate-limit test targeted a firewall-exempt route | All non-static/non-OPTIONS application routes pass through the firewall. Rate-limit test now exercises `/api/status` in the automated suite. |
| `Flask-Cors` missing from requirements | Added the dependency; CORS is disabled unless exact trusted origins are configured. |
| Weak fallback admin/Flask secrets | Removed insecure default secret values; app startup refuses missing, placeholder, or weak secrets. |
| SQLite connection contexts were not explicitly closed | Added a connection context manager that commits/rolls back and closes connections. |
| Database backup copied the live DB file directly | Uses SQLite's online backup API. |
| Forwarded-record percentage labelled PDR | Metric is now `forwarded_record_rate`; reports explicitly state it is not packet delivery ratio. |
| Sender scripts hardcoded a dummy shared secret | Sender/simulator read the configured device secret rather than silently using the old placeholder. |
| Duplicate browser revoke function | Removed the overriding duplicate so `revoked_at` is retained. |
| No LAN evidence utility | Added `lan_test_client.py` to record application-level HTTP response/acceptance, round-trip latency, and accepted records/second to JSON/CSV. |

## Tests run in this environment

- Python syntax compilation (`compileall`): **PASS**.
- Flask automated regression suite: **13/13 PASS**.
- Live HTTP startup smoke test (`GET /api/status` against a running local process): **PASS**, HTTP 200.
- Tests cover valid/forged HMAC, unapproved device, stale/invalid timestamp, out-of-range and empty sensor values, oversized request, rate limit, untrusted forwarded-IP header, proxy localhost-bypass prevention, remote backup authorization, report HTML escaping, and status availability.

The runtime tests used the compatible Python package sources bundled with the supplied project archive because this execution environment could not reach the package index. A clean dependency installation on the user's Windows laptop should still be run with `python -m pip install -r requirements.txt`.

## Not yet verified

- Two physical laptops communicating over the user's actual Wi-Fi/LAN.
- Windows Firewall rules, the user's actual subnet, and any VPN/router/client isolation.
- Real ESP32 hardware, DHT22/MQ-135 readings, actual PoultryVantage cloud endpoint, and mobile application integration.
- Actual IP packet loss. `lan_test_client.py` reports application-level HTTP response failures; use Windows `ping -n 30 <gateway-ip>` separately for network packet-loss evidence.
- Production deployment readiness. Rate limiting remains in-memory; timestamp freshness does not prevent replay within the allowed time window; HTTPS/reverse-proxy deployment and a nonce replay cache need additional design/testing before production.

## Important setup reminders

1. Never copy the original `.env`, database, backups, logs, virtual environment, or executables into the source ZIP.
2. Rotate any real credentials that were present in the original uploaded archive.
3. Keep the gateway local-only by default. For a two-laptop test, use `GATEWAY_HOST=0.0.0.0` and allow only the actual private LAN subnet; never restore `0.0.0.0/0`.
4. Do not copy the gateway admin key or Flask secret to the client laptop. The second laptop only needs the device shared secret used for HMAC test telemetry.
