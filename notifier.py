import os
import requests
import logging

logger = logging.getLogger("gateway")
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "")

def send_admin_alert(device_id, client_ip, reason="Attempted connection without permission"):
    """Sends an instant alert to the administrator via webhook."""
    if not ALERT_WEBHOOK_URL:
        logger.info(f"[ALERT - NO WEBHOOK CONFIGURED] Device: {device_id} | IP: {client_ip} | Reason: {reason}")
        return

    payload = {
        "content": f"🚨 **Gateway Access Request / Security Alert**\n"
                   f"- **Device ID:** `{device_id}`\n"
                   f"- **Source IP:** `{client_ip}`\n"
                   f"- **Status:** `{reason}`\n"
                   f"- **Action Required:** Access must be manually approved by administrator."
    }

    try:
        requests.post(ALERT_WEBHOOK_URL, json=payload, timeout=5)
    except Exception as exc:
        logger.error(f"Failed to deliver admin alert: {exc}")