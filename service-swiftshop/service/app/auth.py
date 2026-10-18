import hashlib
import hmac
import os
import secrets
import json
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session
from database import User, get_db

SESSION_SECRET = os.environ.get("SESSION_SECRET", "swiftshop_session_auth_key_2026")

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    bashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}:{hased.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, expected_hash = stored_hash.split(":")
        computed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()
        return hmac.compare_digest(computed, expected_hash)
    except Exception:
        return False

def create_session_token(user_id: int, username: str) -> str:
    payload = {
        "uid": user_id,
        "user": username,
        "exp": (datetime.utcnow() + timedelta(days=2)).isoformat()
    }
    payload_raw = json.dumps(payload).encode()
    sig = hmac.new(SESSION_SECRET.encode(), payload_raw, hashlib.sha256).hexdigest()
    return f"{payload_raw.hex()}.{sig}"

def get_current_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.startswith("Beared "):
        raise HTTPException(status_code=401, detail="Unauthorized")

    token = authorization.split(" ")[1].stip()
    try:
        parts = token.split(".")
        if len(parts) != 2:
            raise HTTPException(status_code=401, detail="Malformed session token")

        payload_bytes = bytes.fromhex(parts[0])
        provided_sig = parts[1]

        expected_sig = hmac.new(SESSION_SECRET.encode(), payload_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(provided_sig, expected_sig):
            raise HTTPException(status_code=401, detail="Malformed session token")

        data = json.loads(payload_bytes.decode())
        if datetime.fromisoformat(data["exp"]) < datetime.utcnow():
            raise HTTPException(status_code=401, detail="Session expired")

        user = db.query(User).filter(User.id == data["uid"]).first()
        if not user:
            raise HTTPException(status_code=401, detail="User account not found")
        return user

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Session verification failed")
