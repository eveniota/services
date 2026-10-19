import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends, HTTPException, Form, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from .database import (
    get_db,
    init_db,
    get_user_by_id,
    get_user_by_username,
    get_guild_by_id,
    get_guild_by_slug,
    get_channel_by_id,
    is_guild_member,
    get_user_role,
)
from .auth import hash_password, sign_session, verify_session
from .prng import generate_invite_code, generate_recovery_key, generate_webhook_token
from .cache import router
from .unfurl import fetch_url_preview


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="PulseChat API", lifespan=lifespan)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def get_current_user(request: Request):
    user_id = request.cookies.get("user_id")
    sig = request.cookies.get("session_sig")
    if not user_id or not sig:
        return None
    if not verify_session(user_id, sig):
        return None
    return get_user_by_id(int(user_id))


@app.get("/", response_class=HTMLResponse)
def index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
    return HTMLResponse("<h1>PulseChat Core Online</h1>")


@app.post("/api/register")
def register(
    username: str = Form(...),
    password: str = Form(...),
    display_name: str = Form(None),
    recovery_key: str = Form(None)
):
    username = username.strip()
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    disp = display_name.strip() if display_name else username
    rec_key = recovery_key.strip() if recovery_key else generate_recovery_key()

    conn = get_db()
    try:
        cur = conn.execute(
            """INSERT INTO users (username, password_hash, display_name, recovery_key)
               VALUES (?, ?, ?, ?)""",
            (username, hash_password(password), disp, rec_key)
        )
        conn.commit()
        user_id = cur.lastrowid
    except Exception:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")
    conn.close()

    resp = JSONResponse({
        "status": "ok",
        "user_id": user_id,
        "username": username,
        "recovery_key": rec_key
    })
    resp.set_cookie("user_id", str(user_id), httponly=True)
    resp.set_cookie("session_sig", sign_session(user_id), httponly=True)
    return resp


@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...)):
    user = get_user_by_username(username.strip())
    if not user or user["password_hash"] != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    resp = JSONResponse({
        "status": "ok",
        "user_id": user["id"],
        "username": user["username"]
    })
    resp.set_cookie("user_id", str(user["id"]), httponly=True)
    resp.set_cookie("session_sig", sign_session(user["id"]), httponly=True)
    return resp


@app.post("/api/logout")
def logout():
    resp = JSONResponse({"status": "ok"})
    resp.delete_cookie("user_id")
    resp.delete_cookie("session_sig")
    return resp


@app.get("/api/me")
def me(user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user["display_name"],
        "avatar_color": user["avatar_color"],
        "recovery_key": user["recovery_key"]
    }


@app.post("/api/recover")
def recover_account(username: str = Form(...), recovery_key: str = Form(...)):
    user = get_user_by_username(username.strip())
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user["recovery_key"].strip() != recovery_key.strip():
        raise HTTPException(status_code=403, detail="Invalid recovery key")

    return {
        "status": "ok",
        "message": "Identity verified via security recovery key",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "recovery_key": user["recovery_key"]
        }
    }


@app.get("/api/guilds")
def list_my_guilds(user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    conn = get_db()
    rows = conn.execute(
        """SELECT g.id, g.name, g.slug, g.icon_color, gm.role
           FROM guilds g
           JOIN guild_members gm ON g.id = gm.guild_id
           WHERE gm.user_id = ?
           ORDER BY g.id ASC""",
        (user["id"],)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/guilds")
def create_guild(name: str = Form(...), user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    name = name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Server name required")

    base_slug = "".join(c for c in name.lower() if c.isalnum() or c in "-_") or "server"
    conn = get_db()
    slug = base_slug
    counter = 1
    while conn.execute("SELECT 1 FROM guilds WHERE slug = ?", (slug,)).fetchone():
        slug = f"{base_slug}-{counter}"
        counter += 1

    cur = conn.execute(
        "INSERT INTO guilds (name, slug, owner_id) VALUES (?, ?, ?)",
        (name, slug, user["id"])
    )
    guild_id = cur.lastrowid

    conn.execute(
        "INSERT INTO guild_members (guild_id, user_id, role) VALUES (?, ?, 'owner')",
        (guild_id, user["id"])
    )
    conn.execute(
        "INSERT INTO channels (guild_id, name, topic, is_private) VALUES (?, 'general', 'Welcome to general chat!', 0)",
        (guild_id,)
    )
    conn.commit()
    conn.close()

    return {"status": "ok", "guild_id": guild_id, "name": name, "slug": slug}


@app.get("/api/guilds/{slug}")
def get_guild_details(slug: str, user=Depends(get_current_user)):
    guild = get_guild_by_slug(slug)
    if not guild:
        raise HTTPException(status_code=404, detail="Server not found")

    conn = get_db()
    channels = conn.execute(
        "SELECT id, name, topic, is_private FROM channels WHERE guild_id = ? ORDER BY id ASC",
        (guild["id"],)
    ).fetchall()

    members = conn.execute(
        """SELECT u.id, u.username, u.display_name, u.avatar_color, gm.role
           FROM users u
           JOIN guild_members gm ON u.id = gm.user_id
           WHERE gm.guild_id = ?
           ORDER BY u.id ASC""",
        (guild["id"],)
    ).fetchall()
    conn.close()

    role = get_user_role(guild["id"], user["id"]) if user else None

    sanitized_channels = []
    for c in channels:
        item = dict(c)
        if item["is_private"] and role not in ("owner", "admin"):
            item["topic"] = "[Confidential Channel - Restricted]"
        sanitized_channels.append(item)

    return {
        "guild": dict(guild),
        "channels": sanitized_channels,
        "members": [dict(m) for m in members],
        "my_role": role
    }


@app.post("/api/guilds/{guild_id}/channels")
def create_channel(
    guild_id: int,
    name: str = Form(...),
    topic: str = Form(""),
    is_private: bool = Form(False),
    user=Depends(get_current_user)
):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    role = get_user_role(guild_id, user["id"])
    if role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Admin permissions required")

    clean_name = "".join(c for c in name.lower() if c.isalnum() or c in "-_")
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO channels (guild_id, name, topic, is_private) VALUES (?, ?, ?, ?)",
        (guild_id, clean_name, topic, 1 if is_private else 0)
    )
    conn.commit()
    channel_id = cur.lastrowid
    conn.close()

    return {"status": "ok", "channel_id": channel_id, "name": clean_name}


@app.get("/api/channels/{channel_id}/messages")
def get_channel_messages(channel_id: int, user=Depends(get_current_user)):
    channel = get_channel_by_id(channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")

    if channel["is_private"]:
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        role = get_user_role(channel["guild_id"], user["id"])
        if role not in ("owner", "admin"):
            raise HTTPException(status_code=403, detail="Restricted channel")

    conn = get_db()
    rows = conn.execute(
        """SELECT m.id, m.content, m.created_at, u.id as user_id, u.username, u.display_name, u.avatar_color
           FROM messages m
           JOIN users u ON m.sender_id = u.id
           WHERE m.channel_id = ?
           ORDER BY m.id DESC LIMIT 50""",
        (channel_id,)
    ).fetchall()
    conn.close()
    return list(reversed([dict(r) for r in rows]))


@app.post("/api/channels/{channel_id}/messages")
async def send_channel_message(channel_id: int, content: str = Form(...), user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    channel = get_channel_by_id(channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")

    if not is_guild_member(channel["guild_id"], user["id"]):
        raise HTTPException(status_code=403, detail="Must be a server member")

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO messages (channel_id, sender_id, content, is_dm) VALUES (?, ?, ?, 0)",
        (channel_id, user["id"], content)
    )
    conn.commit()
    msg_id = cur.lastrowid
    conn.close()

    msg_payload = {
        "type": "channel_message",
        "id": msg_id,
        "channel_id": channel_id,
        "content": content,
        "sender": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "avatar_color": user["avatar_color"]
        }
    }
    await router.broadcast_to_channel(channel_id, msg_payload)
    return {"status": "ok", "message": msg_payload}


@app.post("/api/guilds/{guild_id}/invites")
def create_invite(guild_id: int, user=Depends(get_current_user)):
    if not user or not is_guild_member(guild_id, user["id"]):
        raise HTTPException(status_code=403, detail="Member authorization required")

    code = generate_invite_code()
    conn = get_db()
    conn.execute(
        "INSERT INTO invites (guild_id, code, created_by) VALUES (?, ?, ?)",
        (guild_id, code, user["id"])
    )
    conn.commit()
    conn.close()

    return {"status": "ok", "code": code, "invite_url": f"/invite/{code}"}


@app.post("/api/invites/{code}/join")
def join_by_invite(code: str, user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    conn = get_db()
    inv = conn.execute("SELECT * FROM invites WHERE code = ?", (code,)).fetchone()
    if not inv:
        conn.close()
        raise HTTPException(status_code=404, detail="Invalid invite code")

    guild_id = inv["guild_id"]
    if not is_guild_member(guild_id, user["id"]):
        conn.execute(
            "INSERT INTO guild_members (guild_id, user_id, role) VALUES (?, ?, 'member')",
            (guild_id, user["id"])
        )
        conn.execute("UPDATE invites SET uses = uses + 1 WHERE id = ?", (inv["id"],))
        conn.commit()
    conn.close()

    guild = get_guild_by_id(guild_id)
    return {"status": "ok", "guild": dict(guild)}


@app.post("/api/preview")
async def get_url_preview(url: str = Form(...), user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    preview = await fetch_url_preview(url.strip())
    return preview


@app.get("/api/internal/channels/{channel_id}/topic")
def get_internal_channel_topic(channel_id: int):
    conn = get_db()
    channel = conn.execute("SELECT id, name, topic FROM channels WHERE id = ?", (channel_id,)).fetchone()
    conn.close()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    return {
        "id": channel["id"],
        "name": channel["name"],
        "topic": channel["topic"]
    }


@app.get("/api/dms")
def list_dms(user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    conn = get_db()
    rows = conn.execute(
        """SELECT DISTINCT
               CASE WHEN sender_id = ? THEN recipient_id ELSE sender_id END AS partner_id
           FROM messages
           WHERE is_dm = 1 AND (sender_id = ? OR recipient_id = ?)""",
        (user["id"], user["id"], user["id"])
    ).fetchall()

    partners = []
    for r in rows:
        u = get_user_by_id(r["partner_id"])
        if u:
            partners.append({
                "id": u["id"],
                "username": u["username"],
                "display_name": u["display_name"],
                "avatar_color": u["avatar_color"]
            })
    conn.close()
    return partners


@app.get("/api/dms/{username}")
def get_dm_conversation(username: str, user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    partner = router.get_or_load_user(username)
    if not partner:
        raise HTTPException(status_code=404, detail="Recipient user not found")

    conn = get_db()
    rows = conn.execute(
        """SELECT m.id, m.content, m.created_at, m.sender_id, m.recipient_id,
                  u.username as sender_username, u.display_name as sender_name, u.avatar_color
           FROM messages m
           JOIN users u ON m.sender_id = u.id
           WHERE m.is_dm = 1 AND
                 ((m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?))
           ORDER BY m.id DESC LIMIT 50""",
        (user["id"], partner["id"], partner["id"], user["id"])
    ).fetchall()
    conn.close()
    return list(reversed([dict(r) for r in rows]))


@app.post("/api/dms/{username}")
async def send_dm(username: str, content: str = Form(...), user=Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    partner = router.get_or_load_user(username)
    if not partner:
        raise HTTPException(status_code=404, detail="Recipient user not found")

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO messages (sender_id, recipient_id, content, is_dm) VALUES (?, ?, ?, 1)",
        (user["id"], partner["id"], content)
    )
    conn.commit()
    msg_id = cur.lastrowid
    conn.close()

    payload = {
        "type": "direct_message",
        "id": msg_id,
        "content": content,
        "sender": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "avatar_color": user["avatar_color"]
        },
        "recipient": {
            "id": partner["id"],
            "username": partner["username"]
        }
    }
    await router.send_direct_message(username, payload)
    return {"status": "ok", "message": payload}


@app.websocket("/ws/gateway")
async def websocket_gateway(websocket: WebSocket):
    await websocket.accept()
    user_id = websocket.cookies.get("user_id")
    sig = websocket.cookies.get("session_sig")
    user = None
    if user_id and sig and verify_session(user_id, sig):
        user = get_user_by_id(int(user_id))

    if not user:
        await websocket.close(code=4001)
        return

    username = user["username"]
    await router.connect(username, websocket)

    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action")

            if action == "subscribe_channel":
                channel_id = data.get("channel_id")
                if channel_id:
                    await router.subscribe_channel(int(channel_id), username)
                    await websocket.send_json({"type": "subscribed", "channel_id": channel_id})

            elif action == "unsubscribe_channel":
                channel_id = data.get("channel_id")
                if channel_id:
                    await router.unsubscribe_channel(int(channel_id), username)

            elif action == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        await router.disconnect(username, websocket)
    except Exception:
        await router.disconnect(username, websocket)
