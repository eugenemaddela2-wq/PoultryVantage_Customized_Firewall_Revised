import json
import time
import requests

from config import CLOUD_ENDPOINT, CLOUD_TIMEOUT_SECONDS


def forward_payload(payload_text: str):
    if not CLOUD_ENDPOINT:
        raise RuntimeError("CLOUD_ENDPOINT is not configured")
    payload = json.loads(payload_text)
    start = time.perf_counter()
    response = requests.post(CLOUD_ENDPOINT, json=payload, timeout=CLOUD_TIMEOUT_SECONDS)
    latency_ms = (time.perf_counter() - start) * 1000
    response.raise_for_status()
    return latency_ms
