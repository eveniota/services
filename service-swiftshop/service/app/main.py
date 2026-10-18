import os
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from jinja2 import Template

from .database import (
    init_db, get_db, User, Product, Order, 
    SupplierContract, ExecutiveVaultItem
)
from .auth import (
    hash_password, verify_password, create_session_token, 
    get_current_user
)
from .voucher import (
    generate_welcome_voucher, verify_voucher_token
)

app = FastAPI(title="SwiftShop Commerce API", version="1.0.0")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def serve_index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class CheckoutRequest(BaseModel):
    item_sku: str
    recipient_name: str
    delivery_address: str
    delivery_instructions: Optional[str] = ""


class InvoicePreviewRequest(BaseModel):
    custom_memo: str


class RedeemVoucherRequest(BaseModel):
    voucher_token: str


class StoreContractRequest(BaseModel):
    contract_reference: str
    partner_name: str
    confidential_memo: str
    authorized_signer: str


class StoreVaultItemRequest(BaseModel):
    vault_id: str
    title: str
    access_token: str


@app.post("/api/auth/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if len(req.username.strip()) < 3 or len(req.password.strip()) < 4:
        raise HTTPException(status_code=400, detail="Username and password too short")

    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")

    new_user = User(
        username=req.username,
        password_hash=hash_password(req.password),
        tier="standard",
        store_credit=10
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_session_token(new_user.id, new_user.username)
    welcome_voucher = generate_welcome_voucher(new_user.username)

    return {
        "status": "success",
        "token": token,
        "welcome_voucher": welcome_voucher,
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "tier": new_user.tier,
            "store_credit": new_user.store_credit
        }
    }


@app.post("/api/auth/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_session_token(user.id, user.username)
    return {
        "status": "success",
        "token": token,
        "welcome_voucher": generate_welcome_voucher(user.username),
        "user": {
            "id": user.id,
            "username": user.username,
            "tier": user.tier,
            "store_credit": user.store_credit
        }
    }


@app.get("/api/auth/me")
def get_profile(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "tier": current_user.tier,
        "store_credit": current_user.store_credit,
        "voucher": generate_welcome_voucher(current_user.username)
    }


@app.get("/api/catalog/products")
def list_products(db: Session = Depends(get_db)):
    products = db.query(Product).filter(Product.is_executive_only == False).all()
    return [{"sku": p.sku, "name": p.name, "description": p.description, "price": p.price} for p in products]


@app.post("/api/orders/checkout")
def checkout_order(req: CheckoutRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    product = db.query(Product).filter(Product.sku == req.item_sku).first()
    price = product.price if product else 49.99

    order = Order(
        user_id=current_user.id,
        item_sku=req.item_sku,
        total_amount=price,
        recipient_name=req.recipient_name,
        delivery_address=req.delivery_address,
        delivery_instructions=req.delivery_instructions
    )
    db.add(order)
    db.commit()
    db.refresh(order)

    return {
        "status": "success",
        "order_id": order.id,
        "total_amount": order.total_amount,
        "dispatch_status": order.status
    }


@app.get("/api/orders/recent")
def list_recent_orders(db: Session = Depends(get_db)):
    orders = db.query(Order).order_by(Order.created_at.desc()).limit(20).all()
    return [
        {
            "order_id": o.id,
            "status": o.status,
            "timestamp": o.created_at.isoformat()
        }
        for o in orders
    ]


@app.get("/api/orders/my-orders")
def get_user_orders(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    orders = db.query(Order).filter(Order.user_id == current_user.id).order_by(Order.created_at.desc()).all()
    return [
        {
            "order_id": o.id,
            "item_sku": o.item_sku,
            "total_amount": o.total_amount,
            "recipient_name": o.recipient_name,
            "delivery_address": o.delivery_address,
            "delivery_instructions": o.delivery_instructions,
            "status": o.status,
            "created_at": o.created_at.isoformat()
        }
        for o in orders
    ]


@app.get("/api/orders/{order_id}")
def get_order_details(order_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if order.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Unauthorized access to order")

    return {
        "order_id": order.id,
        "item_sku": order.item_sku,
        "total_amount": order.total_amount,
        "delivery_instructions": order.delivery_instructions,
        "status": order.status
    }


@app.get("/api/orders/{order_id}/dispatch")
def get_order_dispatch_summary(order_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Dispatch order not found")

    return {
        "order_id": order.id,
        "recipient_name": order.recipient_name,
        "delivery_address": order.delivery_address,
        "delivery_instructions": order.delivery_instructions,
        "dispatch_status": order.status,
        "timestamp": order.created_at.isoformat()
    }


@app.post("/api/contracts/publish")
def publish_contract(req: StoreContractRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    contract = SupplierContract(
        contract_reference=req.contract_reference,
        partner_name=req.partner_name,
        confidential_memo=req.confidential_memo,
        authorized_signer=req.authorized_signer
    )
    db.add(contract)
    db.commit()
    return {"status": "success", "reference": req.contract_reference}


@app.get("/api/contracts/{reference}")
def get_contract(reference: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    contract = db.query(SupplierContract).filter(SupplierContract.contract_reference == reference).first()
    if not contract:
        raise HTTPException(status_code=404, detail="Contract reference not found")
    return {
        "reference": contract.contract_reference,
        "partner_name": contract.partner_name,
        "confidential_memo": contract.confidential_memo,
        "authorized_signer": contract.authorized_signer
    }


@app.post("/api/orders/{order_id}/invoice/preview")
def preview_custom_invoice(order_id: str, req: InvoicePreviewRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    order = db.query(Order).filter(Order.id == order_id, Order.user_id == current_user.id).first()
    if not order:
        raise HTTPException(status_code=403, detail="Order does not exist or unauthorized")

    template_code = f"""
    <div class="receipt-header">
        <h3>SwiftShop Commercial Invoice #{order.id}</h3>
        <p>Customer: {current_user.username} | Total: ${order.total_amount:.2f}</p>
    </div>
    <div class="receipt-memo">
        {req.custom_memo}
    </div>
    """

    try:
        rendered = Template(template_code).render(
            customer=current_user.username,
            order_id=order.id,
            amount=order.total_amount
        )
        return {"status": "success", "rendered_html": rendered}
    except Exception as e:
        return {"status": "error", "message": f"Template compilation failed: {str(e)}"}


@app.post("/api/vouchers/redeem")
def redeem_voucher(req: RedeemVoucherRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        voucher_data = verify_voucher_token(req.voucher_token)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if voucher_data["tier"] == "executive":
        current_user.tier = "executive"

    current_user.store_credit += voucher_data["credit"]
    db.commit()

    return {
        "status": "success",
        "upgraded_tier": current_user.tier,
        "new_balance": current_user.store_credit
    }


@app.post("/api/vault/deposit")
def deposit_vault_item(req: StoreVaultItemRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    item = ExecutiveVaultItem(
        id=req.vault_id,
        title=req.title,
        access_token=req.access_token
    )
    db.merge(item)
    db.commit()
    return {"status": "success", "vault_id": req.vault_id}


@app.get("/api/vault/recent")
def list_recent_vault_items(db: Session = Depends(get_db)):
    items = db.query(ExecutiveVaultItem).limit(20).all()
    return [{"vault_id": i.id, "title": i.title} for i in items]


@app.get("/api/vault/{vault_id}")
def retrieve_vault_item(vault_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.tier != "executive":
        raise HTTPException(
            status_code=403, 
            detail="Access restricted: Requires verified Executive Account tier"
        )

    item = db.query(ExecutiveVaultItem).filter(ExecutiveVaultItem.id == vault_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Vault asset not found")

    return {
        "vault_id": item.id,
        "title": item.title,
        "access_token": item.access_token
    }