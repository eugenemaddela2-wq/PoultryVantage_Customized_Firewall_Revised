"""Environment-backed configuration with conservative development defaults."""
import json
import os
from dotenv import load_dotenv

load_dotenv()

def _int_env(name, default, minimum=1):
    try:
        value = int(os.getenv(name, str(default)))
        return value if value >= minimum else default
    except (TypeError, ValueError):
        return default

HOST = os.getenv("GATEWAY_HOST", "127.0.0.1").strip() or "127.0.0.1"
PORT = _int_env("GATEWAY_PORT", 5000)
CLOUD_ENDPOINT = os.getenv("CLOUD_ENDPOINT", "").strip()
CLOUD_TIMEOUT_SECONDS = _int_env("CLOUD_TIMEOUT_SECONDS", 5)
RETRY_INTERVAL_SECONDS = _int_env("RETRY_INTERVAL_SECONDS", 15)
MAX_RETRY_ATTEMPTS = _int_env("MAX_RETRY_ATTEMPTS", 10)
DB_PATH = os.getenv("DB_PATH", "data/gateway.db")
LOG_PATH = os.getenv("LOG_PATH", "logs/gateway.log")
BACKUP_DIR = os.getenv("BACKUP_DIR", "backups")
BACKUP_INTERVAL_SECONDS = _int_env("BACKUP_INTERVAL_SECONDS", 86400)
MAX_PAYLOAD_BYTES = _int_env("MAX_PAYLOAD_BYTES", 65536)
MAX_TIMESTAMP_AGE_SECONDS = _int_env("MAX_TIMESTAMP_AGE_SECONDS", 300)

try:
    DEVICE_SECRETS = json.loads(os.getenv("DEVICE_SECRETS", "{}"))
    if not isinstance(DEVICE_SECRETS, dict):
        DEVICE_SECRETS = {}
except (json.JSONDecodeError, TypeError):
    DEVICE_SECRETS = {}

FIREWALL_ALLOWED_SUBNETS = [s.strip() for s in os.getenv("FIREWALL_ALLOWED_SUBNETS", "127.0.0.1/32,::1/128").split(",") if s.strip()]
FIREWALL_BLOCKED_IPS = [s.strip() for s in os.getenv("FIREWALL_BLOCKED_IPS", "").split(",") if s.strip()]
FIREWALL_RATE_LIMIT = _int_env("FIREWALL_RATE_LIMIT", 30)
FIREWALL_RATE_WINDOW = _int_env("FIREWALL_RATE_WINDOW", 10)
FIREWALL_BAN_DURATION = _int_env("FIREWALL_BAN_DURATION", 300)
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "").strip()
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "").strip()
TRUSTED_CORS_ORIGINS = [s.strip() for s in os.getenv("TRUSTED_CORS_ORIGINS", "").split(",") if s.strip()]
TRUSTED_PROXY_IPS = [s.strip() for s in os.getenv("TRUSTED_PROXY_IPS", "").split(",") if s.strip()]
