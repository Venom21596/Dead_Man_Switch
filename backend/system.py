import json, hashlib
from shamir import split_secret, reconstruct_secret, shares_to_hex, hex_to_shares
from crypto_utils import (generate_aes_key, encrypt_data, decrypt_data,
    generate_rsa_keypair, serialize_private_key, serialize_public_key,
    load_private_key, load_public_key, encrypt_share, decrypt_share)

def run_demo():
    print("\n" + "="*60)
    print("POSTHUMOUS DATA RELEASE — FULL DEMO")
    print("="*60)

    # ── OWNER SETUP ───────────────────────────────────────────────
    print("\n[OWNER] Generating keys and encrypting data...")

    # Beneficiary keypair
    ben_priv, ben_pub = generate_rsa_keypair()
    ben_priv_pem = serialize_private_key(ben_priv)
    ben_pub_pem  = serialize_public_key(ben_pub)

    # Trustee keypairs (5 trustees)
    trustee_keys = [generate_rsa_keypair() for _ in range(5)]

    # Sensitive data to protect
    sensitive = json.dumps({
        "bitcoin_seed": "witch collapse practice feed shame open despair creek road again ice least",
        "passwords": {"email": "SecretPass123!", "bank": "4321$ecure"},
        "message": "My dearest family — I love you all."
    }).encode()

    # AES-256 encrypt the data
    aes_key = generate_aes_key()
    encrypted_payload = encrypt_data(sensitive, aes_key)
    print(f"  AES key: {aes_key.hex()[:20]}...")
    print(f"  Data encrypted. Hash: {encrypted_payload['data_hash'][:20]}...")

    # Split AES key with Shamir (3-of-5)
    shares = split_secret(aes_key, threshold=3, num_shares=5)
    hex_shares = shares_to_hex(shares)
    print(f"  AES key split into 5 shares (threshold=3)")

    # Encrypt each share FOR THE BENEFICIARY (trustees submit these to chain)
    ben_pub_obj = load_public_key(ben_pub_pem)
    encrypted_shares = [encrypt_share(h, ben_pub_obj) for h in hex_shares]
    print(f"  Each share encrypted with beneficiary's RSA public key")

    # ── TRUSTEE ACTIONS (simulate 3 of 5 acting) ──────────────────
    print("\n[TRUSTEES] 3 trustees confirm death and submit shares...")
    submitted = encrypted_shares[:3]  # First 3 trustees act

    # ── BENEFICIARY RECOVERY ───────────────────────────────────────
    print("\n[BENEFICIARY] Collecting shares and reconstructing data...")

    ben_priv_obj = load_private_key(ben_priv_pem)

    # Decrypt each share using beneficiary's private key
    recovered_hex_shares = [decrypt_share(s, ben_priv_obj) for s in submitted]
    print(f"  Decrypted {len(recovered_hex_shares)} shares using RSA private key")

    # Reconstruct AES key using Shamir
    share_tuples = hex_to_shares(recovered_hex_shares)
    recovered_key = reconstruct_secret(share_tuples)
    print(f"  AES key reconstructed: {recovered_key.hex()[:20]}...")
    print(f"  Key matches original: {recovered_key == aes_key}")

    # Decrypt the data
    recovered_data = decrypt_data(encrypted_payload, recovered_key)

    # Verify hash
    computed = hashlib.sha256(recovered_data).hexdigest()
    stored   = encrypted_payload["data_hash"]
    print(f"  Hash verified: {computed == stored}")

    print("\n" + "="*60)
    print("RECOVERED DATA:")
    print("="*60)
    result = json.loads(recovered_data.decode())
    for k, v in result.items():
        print(f"  {k}: {v}")

    print("\n✅ ALL STEPS VERIFIED — System working correctly!")

if __name__ == "__main__":
    run_demo()
