import secrets
import string
import httpx
from enochecker3 import (
    ChainDB,
    Enochecker,
    GetflagCheckerTaskMessage,
    HavocCheckerTaskMessage,
    MumbleException,
    PutflagCheckerTaskMessage,
)
from enochecker3.utils import assert_equals, assert_in

SERVICE_NAME = "sentinelauth"
SERVICE_PORT = 8002

checker = Enochecker(SERVICE_NAME, SERVICE_PORT)
app = lambda: checker.app


def random_string(length: int = 10) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


@checker.putflag(0)
async def putflag_audit_log(
    task: PutflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> str:
    client_name = f"App_{random_string(6)}"
    allowed_redirect = "https://app.sentinel.internal"

    reg_resp = await client.post(
        "/api/oauth/clients",
        data={"name": client_name, "allowed_redirect": allowed_redirect},
    )
    if reg_resp.status_code != 200:
        raise MumbleException(f"OAuth client registration failed: {reg_resp.text}")

    client_id = reg_resp.json().get("client_id")

    log_resp = await client.post(
        f"/api/clients/{client_id}/audit-logs",
        data={"event_name": "SecurityAuditRecord", "details": task.flag},
    )
    if log_resp.status_code != 200:
        raise MumbleException("Failed to write audit log entry")

    await db.set("client_id", client_id)
    return client_id


@checker.getflag(0)
async def getflag_audit_log(
    task: GetflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> None:
    try:
        client_id = await db.get("client_id")
    except KeyError as e:
        raise MumbleException("Missing putflag(0) state in DB") from e

    resp = await client.get(f"/api/clients/{client_id}/audit-logs")
    if resp.status_code != 200:
        raise MumbleException("Failed to read audit logs")

    logs = resp.json().get("logs", [])
    combined_details = " ".join([l.get("details", "") for l in logs])

    assert_in(task.flag, combined_details, "Flag not found in audit log records")


@checker.putflag(1)
async def putflag_vault_secret(
    task: PutflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> str:
    username = f"admin_{random_string(8)}"
    password = random_string(16)
    title = f"VaultEntry_{random_string(4)}"

    reg_resp = await client.post(
        "/api/register",
        data={
            "username": username,
            "password": password,
            "role": "superadmin",
            "admin_key": "campus_dean_secret_authorization_key_2026",
        },
    )
    if reg_resp.status_code != 200:
        raise MumbleException("Admin registration failed during putflag(1)")

    token = reg_resp.json().get("token")

    vault_resp = await client.post(
        "/api/admin/vault",
        data={"title": title, "secret_value": task.flag},
        headers={"Authorization": f"Bearer {token}"},
    )
    if vault_resp.status_code != 200:
        raise MumbleException("Failed to store secret into admin vault")

    secret_id = vault_resp.json().get("secret_id")

    await db.set("username", username)
    await db.set("password", password)
    await db.set("secret_id", str(secret_id))

    return str(secret_id)


@checker.getflag(1)
async def getflag_vault_secret(
    task: GetflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> None:
    try:
        username = await db.get("username")
        password = await db.get("password")
    except KeyError as e:
        raise MumbleException("Missing putflag(1) state in DB") from e

    login_resp = await client.post(
        "/api/login",
        data={"username": username, "password": password},
    )
    if login_resp.status_code != 200:
        raise MumbleException("Admin login failed during getflag(1)")

    token = login_resp.json().get("token")

    vault_resp = await client.get(
        "/api/admin/vault",
        headers={"Authorization": f"Bearer {token}"},
    )
    if vault_resp.status_code != 200:
        raise MumbleException("Failed to read admin vault during getflag(1)")

    secrets_list = vault_resp.json().get("secrets", [])
    combined_secrets = " ".join([s.get("secret_value", "") for s in secrets_list])

    assert_in(task.flag, combined_secrets, "Flag not found in admin vault")


@checker.putflag(2)
async def putflag_recovery_key(
    task: PutflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> str:
    username = f"user_{random_string(8)}"
    password = random_string(14)

    reg_resp = await client.post(
        "/api/register",
        data={"username": username, "password": password, "role": "member"},
    )
    if reg_resp.status_code != 200:
        raise MumbleException("User registration failed during putflag(2)")

    user_id = reg_resp.json().get("user_id")

    rec_resp = await client.post(
        "/api/recovery/create",
        data={"user_id": user_id, "seed_phrase": task.flag},
    )
    if rec_resp.status_code != 200:
        raise MumbleException("Failed to create recovery key")

    blob = rec_resp.json().get("encrypted_blob")

    await db.set("username", username)
    await db.set("password", password)
    await db.set("encrypted_blob", blob)
    return blob


@checker.getflag(2)
async def getflag_recovery_key(
    task: GetflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> None:
    try:
        username = await db.get("username")
        password = await db.get("password")
        blob = await db.get("encrypted_blob")
    except KeyError as e:
        raise MumbleException("Missing putflag(2) state in DB") from e

    login_resp = await client.post(
        "/api/login",
        data={"username": username, "password": password},
    )
    if login_resp.status_code != 200:
        raise MumbleException("User login failed during getflag(2)")

    token = login_resp.json().get("token")

    restore_resp = await client.post(
        "/api/recovery/restore",
        json={"encrypted_blob": blob},
        headers={"Authorization": f"Bearer {token}"},
    )
    if restore_resp.status_code != 200:
        raise MumbleException("Legitimate recovery key restore failed")

    phrase = restore_resp.json().get("phrase", "")
    assert_equals(phrase, task.flag, "Restored phrase does not match flag")


@checker.havoc(0)
async def havoc_health_check(
    task: HavocCheckerTaskMessage,
    client: httpx.AsyncClient,
) -> None:
    idx_resp = await client.get("/")
    assert_equals(idx_resp.status_code, 200, "Landing page unreachable")

    pk_resp = await client.get("/.well-known/public.pem")
    assert_equals(pk_resp.status_code, 200, "Public key endpoint failed")
    assert_in("BEGIN PUBLIC KEY", pk_resp.text, "Invalid public key format")

    uname = f"test_{random_string(6)}"
    pword = random_string(12)
    reg_resp = await client.post("/api/register", data={"username": uname, "password": pword})
    assert_equals(reg_resp.status_code, 200, "Havoc registration failed")

    log_resp = await client.post("/api/login", data={"username": uname, "password": pword})
    assert_equals(log_resp.status_code, 200, "Havoc login failed")