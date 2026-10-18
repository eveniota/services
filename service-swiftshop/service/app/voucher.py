import base64
import hashlib
import os
from urllib.parse import parse_qs

VOUCHER_SECRET = os.environ.get("VOUCHER_SECRET", "shop_merchant_promokey_prod_32b!").encode()


def generate_welcome_voucher(username: str) -> str:
    payload = f"user={username}&credit=10&tier=standard".encode()
    signature = hashlib.sha256(VOUCHER_SECRET + payload).hexdigest()
    b64_payload = base64.b64encode(payload).decode()
    return f"{b64_payload}.{signature}"


def verify_voucher_token(voucher_token: str) -> dict:
    parts = voucher_token.strip().split(".")
    if len(parts) != 2:
        raise ValueError("Invalid voucher format")

    b64_payload, signature = parts[0], parts[1]
    try:
        payload_bytes = base64.b64decode(b64_payload)
    except Exception:
        raise ValueError("Invalid voucher payload encoding")

    expected_sig = hashlib.sha256(VOUCHER_SECRET + payload_bytes).hexdigest()
    if signature != expected_sig:
        raise ValueError("Voucher cryptographic signature verification failed")

    parsed = parse_qs(payload_bytes.decode("latin-1", errors="ignore"))
    tier = parsed.get("tier", ["standard"])[-1]
    credit = int(parsed.get("credit", [0])[-1])
    target_user = parsed.get("user", [""])[-1]

    return {
        "user": target_user,
        "tier": tier,
        "credit": credit
    }
