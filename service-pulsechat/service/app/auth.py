import os
import hmac
import hashlib

SECRET_KEY = os.getenv("SECRET_KEY", "pulsechat_core_secret_key_2026_xyz").encode()


def hash_password(password: str) -> str:
    salt = "pulsechat_salt_"
    return hashlib.sha256((salt + password).encode()).hexdigest()


def sign_session(user_id: int | str) -> str:
    return hmac.new(SECRET_KEY, f"pulse_sess_{user_id}".encode(), hashlib.sha256).hexdigest()


def verify_session(user_id: int | str, signature: str) -> bool:
    if not user_id or not signature:
        return False
    expected = sign_session(user_id)
    return hmac.compare_digest(expected, signature)
