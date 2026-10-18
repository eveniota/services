import base64
import hashlib
import os
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

SERVICE_NAME = "swiftshop"
SERVICE_PORT = 8003
VOUCHER_SECRET = os.environ.get("VOUCHER_SECRET", "shop_merchant_promokey_prod_32b!").encode()

checker = Enochecker(SERVICE_NAME, SERVICE_PORT)
app = lambda: checker.app


def random_string(length: int = 10) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def create_signed_voucher(username: str, tier: str = "executive", credit: int = 1000) -> str:
    payload = f"user={username}&credit={credit}&tier={tier}".encode()
    signature = hashlib.sha256(VOUCHER_SECRET + payload).hexdigest()
    b64_payload = base64.b64encode(payload).decode()
    return f"{b64_payload}.{signature}"


@checker.putflag(0)
async def putflag_order_dispatch(
    task: PutflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> str:
    username = f"user_{random_string(8)}"
    password = random_string(16)

    reg_resp = await client.post(
        "/api/auth/register",
        json={"username": username, "password": password},
    )
    if reg_resp.status_code != 200:
        raise MumbleException("Registration failed during putflag(0)")

    token = reg_resp.json().get("token")
    headers = {"Authorization": f"Bearer {token}"}

    checkout_resp = await client.post(
        "/api/orders/checkout",
        json={
            "item_sku": "PRD-101",
            "recipient_name": f"Customer_{random_string(6)}",
            "delivery_address": "Suite 500, Tech Park",
            "delivery_instructions": task.flag,
        },
        headers=headers,
    )
    if checkout_resp.status_code != 200:
        raise MumbleException("Order checkout failed during putflag(0)")

    order_id = checkout_resp.json().get("order_id")
    await db.set("order_id", order_id)
    await db.set("token", token)
    return order_id


@checker.getflag(0)
async def getflag_order_dispatch(
    task: GetflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> None:
    try:
        order_id = await db.get("order_id")
        token = await db.get("token")
    except KeyError as e:
        raise MumbleException("Missing putflag(0) state in DB") from e

    resp = await client.get(
        f"/api/orders/{order_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code != 200:
        raise MumbleException("Failed to retrieve order details")

    data = resp.json()
    assert_equals(task.flag, data.get("delivery_instructions"), "Delivery instructions mismatch")


@checker.putflag(1)
async def putflag_supplier_contract(
    task: PutflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> str:
    username = f"partner_{random_string(8)}"
    password = random_string(16)

    reg_resp = await client.post(
        "/api/auth/register",
        json={"username": username, "password": password},
    )
    if reg_resp.status_code != 200:
        raise MumbleException("Registration failed during putflag(1)")

    token = reg_resp.json().get("token")
    headers = {"Authorization": f"Bearer {token}"}

    reference = f"CTR-{random_string(8).upper()}"
    contract_resp = await client.post(
        "/api/contracts/publish",
        json={
            "contract_reference": reference,
            "partner_name": f"Vendor_{random_string(6)}",
            "confidential_memo": task.flag,
            "authorized_signer": "AuditOfficer",
        },
        headers=headers,
    )
    if contract_resp.status_code != 200:
        raise MumbleException("Failed to publish supplier contract")

    await db.set("reference", reference)
    await db.set("token", token)
    return reference


@checker.getflag(1)
async def getflag_supplier_contract(
    task: GetflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> None:
    try:
        reference = await db.get("reference")
        token = await db.get("token")
    except KeyError as e:
        raise MumbleException("Missing putflag(1) state in DB") from e

    resp = await client.get(
        f"/api/contracts/{reference}",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code != 200:
        raise MumbleException("Failed to retrieve supplier contract")

    data = resp.json()
    assert_equals(task.flag, data.get("confidential_memo"), "Supplier contract memo mismatch")


@checker.putflag(2)
async def putflag_executive_vault(
    task: PutflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> str:
    username = f"exec_{random_string(8)}"
    password = random_string(16)

    reg_resp = await client.post(
        "/api/auth/register",
        json={"username": username, "password": password},
    )
    if reg_resp.status_code != 200:
        raise MumbleException("Registration failed during putflag(2)")

    token = reg_resp.json().get("token")
    headers = {"Authorization": f"Bearer {token}"}

    voucher_token = create_signed_voucher(username, tier="executive", credit=5000)
    redeem_resp = await client.post(
        "/api/vouchers/redeem",
        json={"voucher_token": voucher_token},
        headers=headers,
    )
    if redeem_resp.status_code != 200:
        raise MumbleException("Voucher redemption failed during putflag(2)")

    vault_id = f"VLT-{random_string(8).upper()}"
    deposit_resp = await client.post(
        "/api/vault/deposit",
        json={
            "vault_id": vault_id,
            "title": f"Executive Asset {random_string(4)}",
            "access_token": task.flag,
        },
        headers=headers,
    )
    if deposit_resp.status_code != 200:
        raise MumbleException("Failed to deposit vault asset")

    await db.set("vault_id", vault_id)
    await db.set("token", token)
    return vault_id


@checker.getflag(2)
async def getflag_executive_vault(
    task: GetflagCheckerTaskMessage,
    client: httpx.AsyncClient,
    db: ChainDB,
) -> None:
    try:
        vault_id = await db.get("vault_id")
        token = await db.get("token")
    except KeyError as e:
        raise MumbleException("Missing putflag(2) state in DB") from e

    resp = await client.get(
        f"/api/vault/{vault_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code != 200:
        raise MumbleException("Failed to retrieve vault asset")

    data = resp.json()
    assert_equals(task.flag, data.get("access_token"), "Vault asset access token mismatch")


@checker.havoc(0)
async def havoc_storefront_flow(
    task: HavocCheckerTaskMessage,
    client: httpx.AsyncClient,
) -> None:
    cat_resp = await client.get("/api/catalog/products")
    if cat_resp.status_code != 200 or not isinstance(cat_resp.json(), list):
        raise MumbleException("Product catalog endpoint unavailable")

    username = f"shopper_{random_string(8)}"
    password = random_string(16)

    reg_resp = await client.post(
        "/api/auth/register",
        json={"username": username, "password": password},
    )
    if reg_resp.status_code != 200:
        raise MumbleException("User registration failed during havoc")

    token = reg_resp.json().get("token")
    headers = {"Authorization": f"Bearer {token}"}

    me_resp = await client.get("/api/auth/me", headers=headers)
    if me_resp.status_code != 200:
        raise MumbleException("User profile verification failed")

    order_resp = await client.post(
        "/api/orders/checkout",
        json={
            "item_sku": "PRD-102",
            "recipient_name": "Test Shopper",
            "delivery_address": "Main Ave 12",
            "delivery_instructions": "Leave at front desk",
        },
        headers=headers,
    )
    if order_resp.status_code != 200:
        raise MumbleException("Checkout failed during havoc")

    order_id = order_resp.json().get("order_id")

    my_orders_resp = await client.get("/api/orders/my-orders", headers=headers)
    if my_orders_resp.status_code != 200:
        raise MumbleException("Order listing failed during havoc")

    invoice_resp = await client.post(
        f"/api/orders/{order_id}/invoice/preview",
        json={"custom_memo": "Standard billing receipt"},
        headers=headers,
    )
    if invoice_resp.status_code != 200:
        raise MumbleException("Invoice preview failed during havoc")

    dispatch_resp = await client.get(f"/api/orders/{order_id}/dispatch", headers=headers)
    if dispatch_resp.status_code != 200:
        raise MumbleException("Dispatch summary lookup failed during havoc")
