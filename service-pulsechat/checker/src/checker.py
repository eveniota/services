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

SERVICE_NAME = "pulsechat"
SERVICE_PORT = 8001
checker = Enochecker(SERVICE_NAME, SERVICE_PORT)
app = lambda: checker.app


def random_string(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


@checker.havoc(0)
async def havoc_chat_flow(task: HavocCheckerTaskMessage, client: httpx.AsyncClient) -> None:
    u = f"havoc_{random_string(6).lower()}"
    p = random_string(16)
    reg_resp = await client.post("/api/register", data={"username": u, "password": p})
    if reg_resp.status_code != 200:
        raise MumbleException(f"Havoc registration failed: {reg_resp.text}")

    g_resp = await client.post("/api/guilds", data={"name": f"Lobby {random_string(4)}"})
    if g_resp.status_code != 200:
        raise MumbleException(f"Havoc server creation failed: {g_resp.text}")

    slug = g_resp.json()["slug"]
    details_resp = await client.get(f"/api/guilds/{slug}")
    if details_resp.status_code != 200:
        raise MumbleException("Could not fetch server details")

    channels = details_resp.json().get("channels", [])
    if not channels:
        raise MumbleException("Default channel not found in server")
    general_id = channels[0]["id"]

    msg_text = f"Test message {random_string(8)}"
    post_resp = await client.post(f"/api/channels/{general_id}/messages", data={"content": msg_text})
    if post_resp.status_code != 200:
        raise MumbleException(f"Failed to post channel message: {post_resp.text}")

    hist_resp = await client.get(f"/api/channels/{general_id}/messages")
    if hist_resp.status_code != 200:
        raise MumbleException("Failed to fetch channel history")

    contents = [m.get("content", "") for m in hist_resp.json()]
    assert_in(msg_text, contents, "Sent message not found in channel feed")


@checker.putflag(0)
async def putflag_channel_topic(
    task: PutflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> str:
    username = f"admin_{random_string(6).lower()}"
    password = random_string(16)
    guild_name = f"Guild {random_string(4)}"

    reg = await client.post("/api/register", data={"username": username, "password": password})
    if reg.status_code != 200:
        raise MumbleException(f"Register failed during putflag(0): {reg.text}")

    g_resp = await client.post("/api/guilds", data={"name": guild_name})
    if g_resp.status_code != 200:
        raise MumbleException("Guild creation failed in putflag(0)")
    guild_id = g_resp.json()["guild_id"]
    slug = g_resp.json()["slug"]

    ch_name = f"confidential-{random_string(4).lower()}"
    ch_resp = await client.post(
        f"/api/guilds/{guild_id}/channels",
        data={"name": ch_name, "topic": task.flag, "is_private": "true"}
    )
    if ch_resp.status_code != 200:
        raise MumbleException("Private channel creation failed in putflag(0)")
    channel_id = ch_resp.json()["channel_id"]

    await db.set("username", username)
    await db.set("password", password)
    await db.set("slug", slug)
    await db.set("channel_id", str(channel_id))

    return str(channel_id)


@checker.getflag(0)
async def getflag_channel_topic(
    task: GetflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> None:
    try:
        username = await db.get("username")
        password = await db.get("password")
        slug = await db.get("slug")
        channel_id = int(await db.get("channel_id"))
    except KeyError as e:
        raise MumbleException(f"Missing db state in getflag(0): {e}")

    login_resp = await client.post("/api/login", data={"username": username, "password": password})
    if login_resp.status_code != 200:
        raise MumbleException("Login failed in getflag(0)")

    guild_resp = await client.get(f"/api/guilds/{slug}")
    if guild_resp.status_code != 200:
        raise MumbleException("Server query failed in getflag(0)")

    channels = guild_resp.json().get("channels", [])
    target = next((c for c in channels if c["id"] == channel_id), None)
    if not target:
        raise MumbleException("Target channel not found in server")

    assert_equals(target.get("topic"), task.flag, "Channel topic flag mismatch")


@checker.putflag(1)
async def putflag_direct_message(
    task: PutflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> str:
    recipient_user = f"recip_{random_string(6).lower()}"
    recipient_pass = random_string(16)
    sender_user = f"sender_{random_string(6).lower()}"
    sender_pass = random_string(16)

    r1 = await client.post("/api/register", data={"username": recipient_user, "password": recipient_pass})
    if r1.status_code != 200:
        raise MumbleException("Recipient registration failed in putflag(1)")

    r2 = await client.post("/api/register", data={"username": sender_user, "password": sender_pass})
    if r2.status_code != 200:
        raise MumbleException("Sender registration failed in putflag(1)")

    dm_resp = await client.post(f"/api/dms/{recipient_user}", data={"content": task.flag})
    if dm_resp.status_code != 200:
        raise MumbleException("Sending DM failed in putflag(1)")

    await db.set("recipient_user", recipient_user)
    await db.set("recipient_pass", recipient_pass)
    await db.set("sender_user", sender_user)

    return recipient_user


@checker.getflag(1)
async def getflag_direct_message(
    task: GetflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> None:
    try:
        recipient_user = await db.get("recipient_user")
        recipient_pass = await db.get("recipient_pass")
        sender_user = await db.get("sender_user")
    except KeyError as e:
        raise MumbleException(f"Missing db state in getflag(1): {e}")

    login_resp = await client.post("/api/login", data={"username": recipient_user, "password": recipient_pass})
    if login_resp.status_code != 200:
        raise MumbleException("Recipient login failed in getflag(1)")

    dms_resp = await client.get(f"/api/dms/{sender_user}")
    if dms_resp.status_code != 200:
        raise MumbleException("DM conversation fetch failed in getflag(1)")

    messages = [m.get("content", "") for m in dms_resp.json()]
    assert_in(task.flag, messages, "Flag not found in DM history")


@checker.putflag(2)
async def putflag_recovery_key(
    task: PutflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> str:
    username = f"vault_{random_string(6).lower()}"
    password = random_string(16)

    reg = await client.post(
        "/api/register",
        data={"username": username, "password": password, "recovery_key": task.flag}
    )
    if reg.status_code != 200:
        raise MumbleException("User registration failed in putflag(2)")

    g_resp = await client.post("/api/guilds", data={"name": f"Vault Server {random_string(4)}"})
    if g_resp.status_code == 200:
        guild_id = g_resp.json().get("guild_id")
        await client.post(f"/api/guilds/{guild_id}/invites")

    await db.set("username", username)
    await db.set("password", password)

    return username


@checker.getflag(2)
async def getflag_recovery_key(
    task: GetflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> None:
    try:
        username = await db.get("username")
        password = await db.get("password")
    except KeyError as e:
        raise MumbleException(f"Missing db state in getflag(2): {e}")

    login_resp = await client.post("/api/login", data={"username": username, "password": password})
    if login_resp.status_code != 200:
        raise MumbleException("Login failed in getflag(2)")

    me_resp = await client.get("/api/me")
    if me_resp.status_code != 200:
        raise MumbleException("Profile retrieval failed in getflag(2)")

    recovery_key = me_resp.json().get("recovery_key")
    assert_equals(recovery_key, task.flag, "Recovery key flag mismatch")
