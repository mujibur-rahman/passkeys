import secrets
import json
import hashlib
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import ENC_KEY, RP_ID
import db

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def _aad(user_id: int) -> bytes:
    return f"{RP_ID}|{user_id}".encode("utf-8")

def encrypt_blob(plaintext: bytes, aad: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    aes = AESGCM(ENC_KEY)
    ct = aes.encrypt(nonce, plaintext, aad)
    return nonce + ct

def constant_work_padding():
    # Spend similar CPU as decrypting a credential; avoids early-return timing gap
    aad = b"pad"
    aes = AESGCM(ENC_KEY)
    fake_nonce = secrets.token_bytes(12)
    fake_ct = secrets.token_bytes(48)  # random bytes
    try:
        aes.decrypt(fake_nonce, fake_ct, aad)  # will fail, but burns comparable work
    except Exception:
        pass

def decrypt_blob(blob: bytes, aad: bytes) -> bytes:
    nonce = blob[:12]
    ct = blob[12:]
    aes = AESGCM(ENC_KEY)
    return aes.decrypt(nonce, ct, aad)

def decrypt_credential_id(row: "db.sqlite3.Row") -> bytes:
    user_id = int(row["user_id"])
    return decrypt_blob(bytes(row["credential_id_enc"]), aad=_aad(user_id))

def decrypt_public_key(row: "db.sqlite3.Row") -> bytes:
    user_id = int(row["user_id"])
    return decrypt_blob(bytes(row["public_key_enc"]), aad=_aad(user_id))

def save_credential(
    user_id: int,
    credential_id: bytes,
    public_key: bytes,
    sign_count: int,
    transports: Optional[list[str]],
    device_type: Optional[str],
    backed_up: bool,
) -> None:
    cred_hash = sha256(credential_id)
    aad = _aad(user_id)
    credential_id_enc = encrypt_blob(credential_id, aad=aad)
    public_key_enc = encrypt_blob(public_key, aad=aad)

    db.insert_or_replace_credential(
        user_id=user_id,
        credential_id_hash=cred_hash,
        credential_id_enc=credential_id_enc,
        public_key_enc=public_key_enc,
        sign_count=sign_count,
        transports_json=json.dumps(transports or []),
        device_type=device_type,
        backed_up=backed_up,
    )

def update_sign_count(
    cred_hash: bytes,
    new_sign_count: int,
    device_type: Optional[str],
    backed_up: bool,
) -> None:
    db.update_credential_sign_count(
        cred_hash=cred_hash,
        new_sign_count=new_sign_count,
        device_type=device_type,
        backed_up=backed_up,
    )