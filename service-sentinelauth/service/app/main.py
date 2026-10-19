import os
import re
import secrets
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Header, Form
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse, FileResponse
from pydantic import BaseModel

from .database import get_db, init_db
from .crypto import (
    hash_password,
    ensure_rsa_keys,
    get_public_key_pem,
    encrypt_recovery_data,
    decrypt_recovery_data,
    PaddingException,
)
from .jwt_auth import create_user_jwt, verify_user_jwt


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    ensure_rsa_keys()
    yield


app = FastAPI(title="CampusPortal Academic ERP", lifespan=lifespan)


def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization.split(" ")[1]
    try:
        payload = verify_user_jwt(token)
        return payload
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.get("/")
def index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))


@app.get("/.well-known/public.pem", response_class=PlainTextResponse)
def get_public_key():
    return get_public_key_pem().decode("utf-8")


ADMIN_REGISTRATION_KEY = os.getenv("ADMIN_REGISTRATION_KEY", "campus_dean_secret_authorization_key_2026")


@app.post("/api/register")
def register(
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("member"),
    admin_key: Optional[str] = Form(None),
):
    if role == "superadmin":
        if admin_key != ADMIN_REGISTRATION_KEY:
            raise HTTPException(
                status_code=403,
                detail="Superadmin registration requires valid institutional authorization key"
            )
    else:
        role = "member"

    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hash_password(password), role),
        )
        conn.commit()
        user_id = cur.lastrowid
    except Exception:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()

    token = create_user_jwt(user_id, username, role)
    return {"status": "ok", "user_id": user_id, "token": token}


@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    user = conn.execute(
        "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?",
        (username, hash_password(password)),
    ).fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    token = create_user_jwt(user["id"], user["username"], user["role"])
    return {"status": "ok", "user_id": user["id"], "role": user["role"], "token": token}


@app.post("/api/oauth/clients")
def register_oauth_client(name: str = Form(...), allowed_redirect: str = Form(...)):
    client_id = f"client_{secrets.token_hex(6)}"
    client_secret = secrets.token_hex(16)

    conn = get_db()
    conn.execute(
        "INSERT INTO oauth_clients (client_id, client_secret, name, allowed_redirect) VALUES (?, ?, ?, ?)",
        (client_id, client_secret, name, allowed_redirect),
    )
    conn.commit()
    conn.close()

    return {"client_id": client_id, "client_secret": client_secret, "allowed_redirect": allowed_redirect}


@app.get("/oauth/authorize")
def oauth_authorize(client_id: str, redirect_uri: str, response_type: str = "code"):
    conn = get_db()
    client = conn.execute(
        "SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)
    ).fetchone()

    if not client:
        conn.close()
        raise HTTPException(status_code=404, detail="Client not found")

    pattern = f"^{re.escape(client['allowed_redirect'])}"
    if not re.match(pattern, redirect_uri):
        conn.close()
        raise HTTPException(status_code=400, detail="Redirect URI not authorized")

    code = f"auth_{secrets.token_hex(12)}"
    conn.execute(
        "INSERT INTO auth_codes (code, client_id, user_id) VALUES (?, ?, ?)",
        (code, client_id, 1),
    )
    conn.commit()
    conn.close()

    return {"status": "authorized", "redirect_to": f"{redirect_uri}?code={code}", "code": code}


@app.post("/oauth/token")
def oauth_exchange_token(
    client_id: str = Form(...),
    client_secret: str = Form(...),
    code: str = Form(...),
):
    conn = get_db()
    client = conn.execute(
        "SELECT * FROM oauth_clients WHERE client_id = ? AND client_secret = ?",
        (client_id, client_secret),
    ).fetchone()

    if not client:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    auth_code = conn.execute(
        "SELECT code FROM auth_codes WHERE code = ? AND client_id = ?",
        (code, client_id),
    ).fetchone()

    if not auth_code:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired authorization code")

    conn.execute("DELETE FROM auth_codes WHERE code = ?", (code,))
    conn.commit()
    conn.close()

    access_token = f"sentinel_tok_{secrets.token_hex(16)}"
    return {"access_token": access_token, "token_type": "Bearer", "client_id": client_id}


@app.post("/api/clients/{client_id}/audit-logs")
def add_audit_log(
    client_id: str,
    event_name: str = Form(...),
    details: str = Form(...),
):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs (client_id, event_name, details) VALUES (?, ?, ?)",
        (client_id, event_name, details),
    )
    conn.commit()
    conn.close()
    return {"status": "ok", "message": "Audit event recorded"}


@app.get("/api/clients/{client_id}/audit-logs")
def get_audit_logs(client_id: str):
    conn = get_db()
    logs = conn.execute(
        "SELECT id, event_name, details, created_at FROM audit_logs WHERE client_id = ?",
        (client_id,),
    ).fetchall()
    conn.close()
    return {"client_id": client_id, "logs": [dict(r) for r in logs]}


@app.post("/api/admin/vault")
def add_vault_secret(
    title: str = Form(...),
    secret_value: str = Form(...),
    user=Depends(get_current_user),
):
    if user.get("role") != "superadmin":
        raise HTTPException(status_code=403, detail="Superadmin access required")

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO vault_secrets (title, secret_value) VALUES (?, ?)",
        (title, secret_value),
    )
    conn.commit()
    secret_id = cur.lastrowid
    conn.close()
    return {"status": "ok", "secret_id": secret_id, "title": title}


@app.get("/api/admin/vault")
def get_vault_secrets(user=Depends(get_current_user)):
    if user.get("role") != "superadmin":
        raise HTTPException(status_code=403, detail="Superadmin access required")

    conn = get_db()
    secrets_list = conn.execute("SELECT id, title, secret_value, created_at FROM vault_secrets").fetchall()
    conn.close()
    return {"secrets": [dict(s) for s in secrets_list]}


class RecoveryRestoreRequest(BaseModel):
    encrypted_blob: str


@app.post("/api/recovery/create")
def create_recovery_key(
    user_id: int = Form(...),
    seed_phrase: str = Form(...),
):
    payload = {"user_id": user_id, "phrase": seed_phrase}
    encrypted_blob = encrypt_recovery_data(payload)

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO recovery_keys (user_id, encrypted_blob) VALUES (?, ?)",
        (user_id, encrypted_blob),
    )
    conn.commit()
    key_id = cur.lastrowid
    conn.close()

    return {"status": "ok", "key_id": key_id, "encrypted_blob": encrypted_blob}


@app.post("/api/recovery/restore")
def restore_recovery_key(
    req: RecoveryRestoreRequest,
    authorization: Optional[str] = Header(None),
):
    try:
        data = decrypt_recovery_data(req.encrypted_blob)
        target_uid = str(data.get("user_id"))

        # If requester is authenticated and owns this student record (or is superadmin), return the phrase
        if authorization and authorization.startswith("Bearer "):
            try:
                user = verify_user_jwt(authorization.split(" ")[1])
                if user.get("sub") == target_uid or user.get("role") == "superadmin":
                    return {
                        "status": "ok",
                        "message": "Recovery key restored successfully",
                        "phrase": data.get("phrase"),
                    }
            except Exception:
                pass

        # Non-owner or unauthenticated callers only receive verification confirmation
        return {
            "status": "ok",
            "message": "Credential backup verified successfully",
            "record_id": target_uid,
        }
    except PaddingException:
        return JSONResponse(status_code=400, content={"error": "Invalid PKCS#7 padding block"})
    except Exception:
        return JSONResponse(status_code=422, content={"error": "Malformed JSON payload structure"})
