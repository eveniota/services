import os
import uuid
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, Float, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DB_PATH = os.environ.get("DB_PATH", "/data/swiftshop.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    tier = Column(String(32), default="standard")
    store_credit = Column(Integer, default=10)
    created_at = Column(DateTime, default=datetime.utcnow)

    orders = relationship("Order", back_populates="user")


class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    sku = Column(String(32), unique=True, nullable=False)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    price = Column(Float, nullable=False)
    is_executive_only = Column(Boolean, default=False)


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    item_sku = Column(String(32), nullable=False)
    total_amount = Column(Float, nullable=False)
    recipient_name = Column(String(128), nullable=False)
    delivery_address = Column(String(256), nullable=False)
    delivery_instructions = Column(Text, nullable=True)
    status = Column(String(32), default="dispatched")
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="orders")


class SupplierContract(Base):
    __tablename__ = "supplier_contracts"

    id = Column(Integer, primary_key=True, index=True)
    contract_reference = Column(String(64), unique=True, nullable=False)
    partner_name = Column(String(128), nullable=False)
    confidential_memo = Column(Text, nullable=False)
    authorized_signer = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class ExecutiveVaultItem(Base):
    __tablename__ = "executive_vault"

    id = Column(String(64), primary_key=True)
    title = Column(String(128), nullable=False)
    access_token = Column(Text, nullable=False)
    tier_required = Column(String(32), default="executive")

class RedeemedVoucher(Base):
    __tablename__ = "redeemed_vouchers"
    id = Column(Integer, primary_key=True, index=True)
    voucher_sig = Column(String(64), unique=True, nullable=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        if db.query(Product).count() == 0:
            catalog = [
                Product(sku="PRD-101", name="Wireless Mechanical Keyboard", description="RGB backlit with hot-swappable switches", price=79.99),
                Product(sku="PRD-102", name="Precision Optical Mouse", description="16000 DPI gaming-grade sensor", price=49.99),
                Product(sku="PRD-103", name="USB-C Dual 4K Docking Station", description="Power delivery up to 100W with Gigabit Ethernet", price=129.99),
                Product(sku="PRD-104", name="Noise-Cancelling Studio Headset", description="Custom tuned 50mm neodymium drivers", price=89.99)
            ]
            db.add_all(catalog)
            db.commit()
    finally:
        db.close()
