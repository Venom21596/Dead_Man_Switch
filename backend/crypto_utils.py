import os, base64, json, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def generate_aes_key():
    return os.urandom(32)

def encrypt_data(plaintext: bytes, key: bytes) -> dict:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "ciphertext": base64.b64encode(ct).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "data_hash": hashlib.sha256(plaintext).hexdigest()
    }

def decrypt_data(enc: dict, key: bytes) -> bytes:
    ct = base64.b64decode(enc["ciphertext"])
    nonce = base64.b64decode(enc["nonce"])
    return AESGCM(key).decrypt(nonce, ct, None)

def generate_rsa_keypair():
    priv = rsa.generate_private_key(65537, 2048, default_backend())
    return priv, priv.public_key()

def serialize_private_key(k):
    return k.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()

def serialize_public_key(k):
    return k.public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()

def load_private_key(pem):
    return serialization.load_pem_private_key(pem.encode(), None, default_backend())

def load_public_key(pem):
    return serialization.load_pem_public_key(pem.encode(), default_backend())

def encrypt_share(share_hex: str, pub_key) -> str:
    ct = pub_key.encrypt(share_hex.encode(),
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    return base64.b64encode(ct).decode()

def decrypt_share(enc_b64: str, priv_key) -> str:
    ct = base64.b64decode(enc_b64)
    return priv_key.decrypt(ct,
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)).decode()

if __name__ == "__main__":
    print("=== Crypto Utils Test ===")
    key = generate_aes_key()
    data = b"Hello secret world!"
    enc = encrypt_data(data, key)
    dec = decrypt_data(enc, key)
    print(f"AES encrypt/decrypt match: {dec == data}")
    priv, pub = generate_rsa_keypair()
    enc_share = encrypt_share("01:abcdef1234", pub)
    dec_share = decrypt_share(enc_share, priv)
    print(f"RSA share encrypt/decrypt match: {dec_share == '01:abcdef1234'}")
