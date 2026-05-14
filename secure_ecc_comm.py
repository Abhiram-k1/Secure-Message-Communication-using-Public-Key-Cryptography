import os
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — KEY GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_ecc_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_ecc_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — KEY EXCHANGE (ECDH) & DERIVATION (HKDF)
# ─────────────────────────────────────────────────────────────────────────────

def derive_shared_secret(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32, # 256-bit key for AES-256
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    
    return derived_key

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — SYMMETRIC ENCRYPTION (AES-GCM)
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_message_aes_gcm(plaintext: str, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return nonce + ciphertext

def decrypt_message_aes_gcm(encrypted_data: bytes, key: bytes) -> str:
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    except Exception:
        raise ValueError("Decryption failed: Integrity check failed or wrong key.")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — DIGITAL SIGNATURES (ECDSA)
# ─────────────────────────────────────────────────────────────────────────────

def sign_message(message: bytes, private_key) -> bytes:
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signature(message: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False
