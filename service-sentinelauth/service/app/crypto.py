import base64
import hashlib
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def hash_password(password: str)-> str:
    return hashlib.sha256(password.encode()).hexdigest()

KEYS_DIR = os.getenv("KEYS_DIR", "/service/keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public.pem")

def ensure_rsa_keys():
    os.makedirs(KEYS_DIR, exist_ok=True)
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(priv_pem)
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(pub_pem)

ensure_rsa_key = ensure_rsa_keys


def get_private_key_pem() -> bytes:
    ensure_rsa_key()
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return f.read()

def get_public_key_pem() -> bytes:
    ensure_rsa_key()
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return f.read()

AES_MASTER_KEY = hashlib.sha256(os.getenv("AES_MASTER_KEY", "sentinel_master_key_32bytes_!!").encode()).digest()

class PaddingException(Exception):
    """Raised specifically when PKCS#7 padding validation fails."""
    pass

def encrypt_recovery_data(payload: dict) -> str:
    data = json.dumps(payload).encode("utf-8")

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_MASTER_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode("utf-8")

def decrypt_recovery_data(b64_blob: str) -> dict:
    raw = base64.b64decode(b64_blob)
    if len(raw) < 32 or len(raw) % 16 != 0:
        raise ValueError("Invalid ciphertext length")

    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = Cipher(algorithms.AES(AES_MASTER_KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    try:
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(decrypted_padded) + unpadder.finalize()
    except ValueError as e:
        raise PaddingException("Invalid PKCS#7 padding block") from e

    try:
        return json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        raise ValueError("Malformed JSON payload structure") from e




