import hashlib
import hmac


def compute_signature(secret: str, raw_body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()


def verify_signature(secret: str, raw_body: bytes, supplied_signature: str) -> bool:
    if not supplied_signature:
        return False
    expected = compute_signature(secret, raw_body)
    return hmac.compare_digest(expected, supplied_signature.strip().lower())
