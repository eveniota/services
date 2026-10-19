import base64
import hmac
import hashlib
import json
import time
import jwt
from .crypto import get_private_key_pem, get_public_key_pem

JWT_ISSUER = "sentinelauth-sso"

def create_user_jwt(user_id: int, username: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "iss": JWT_ISSUER,
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": now,
        "exp": now + 7200,  # 2 hours validity
    }
    return jwt.encode(payload, get_private_key_pem(), algorithm="RS256")

def verify_user_jwt(token: str) -> dict:
    public_pem = get_public_key_pem()
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg")
        if alg == "HS256":
            # Support symmetric fallback validation
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError("Invalid token segments")
            signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
            sig_b64 = parts[2] + "=" * ((4 - len(parts[2]) % 4) % 4)
            signature = base64.urlsafe_b64decode(sig_b64)

            expected_sig = hmac.new(public_pem, signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected_sig):
                stripped = public_pem.replace(b"-----BEGIN PUBLIC KEY-----", b"").replace(b"-----END PUBLIC KEY-----", b"").replace(b"\n", b"").replace(b"\r", b"").strip()
                alt_sig = hmac.new(stripped, signing_input, hashlib.sha256).digest()
                if not hmac.compare_digest(signature, alt_sig):
                    raise ValueError("Signature verification failed")

            payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
            if payload.get("iss") != JWT_ISSUER:
                raise ValueError("Invalid token issuer")
            if payload.get("exp", 0) < time.time():
                raise ValueError("Token expired")
            return payload
        else:
            payload = jwt.decode(
                token,
                public_pem,
                algorithms=["RS256"],
                issuer=JWT_ISSUER,
            )
            return payload
    except jwt.PyJWTError as e:
        raise ValueError(f"Token validation failed: {str(e)}")