import json
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

import db
import crypto_store
from config import RP_ID, ORIGIN, RP_NAME, CHALLENGE_TTL_SECONDS

router = APIRouter()

def b64url_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

@router.post("/api/register/options")
async def register_options(request: Request):
    body = await request.json()
    username = (body.get("username") or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="invalid request")

    user = db.get_user(username)
    if not user:
        user = db.get_or_create_user(username, user_handle=secrets.token_bytes(16))

    creds = db.list_user_credentials(user["id"])

    exclude = []
    for r in creds:
        cred_id = crypto_store.decrypt_credential_id(r)
        exclude.append(PublicKeyCredentialDescriptor(id=cred_id))

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=bytes(user["user_handle"]),
        user_name=username,
        user_display_name=username,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=exclude,
    )

    request.session["reg_challenge"] = b64url_encode(options.challenge)
    request.session["reg_challenge_issued_at"] = int(time.time())

    return JSONResponse(content=json.loads(options_to_json(options)))

@router.post("/api/register/verify")
async def register_verify(request: Request):
    body = await request.json()
    username = (body.get("username") or "").strip()
    credential = body.get("credential")
    if not username or not credential:
        raise HTTPException(status_code=400, detail="invalid request")

    user = db.get_user(username)
    if not user:
        raise HTTPException(status_code=400, detail="invalid request")

    expected_challenge_b64 = request.session.pop("reg_challenge", None)
    issued_at = request.session.pop("reg_challenge_issued_at", None)
    if not expected_challenge_b64 or not issued_at:
        raise HTTPException(status_code=400, detail="registration expired (start over)")
    if int(time.time()) - int(issued_at) > CHALLENGE_TTL_SECONDS:
        raise HTTPException(status_code=400, detail="registration expired (start over)")

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(expected_challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=True,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="webauthn verification failed")

    transports = credential.get("response", {}).get("transports")

    crypto_store.save_credential(
        user_id=user["id"],
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        transports=transports,
        device_type=getattr(verification, "credential_device_type", None),
        backed_up=bool(getattr(verification, "credential_backed_up", False)),
    )

    request.session["user"] = {"username": username}
    return {"verified": True}

@router.post("/api/login/options")
async def login_options(request: Request):
    body = await request.json()
    username = (body.get("username") or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="invalid request")

    user = db.get_user(username)
    if not user:
        raise HTTPException(status_code=400, detail="invalid request")

    creds = db.list_user_credentials(user["id"])
    if not creds:
        raise HTTPException(status_code=400, detail="invalid request")

    allow = []
    for r in creds:
        cred_id = crypto_store.decrypt_credential_id(r)
        allow.append(PublicKeyCredentialDescriptor(id=cred_id))

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    request.session["auth_challenge"] = b64url_encode(options.challenge)
    request.session["auth_challenge_issued_at"] = int(time.time())
    request.session["auth_username"] = username

    return JSONResponse(content=json.loads(options_to_json(options)))

@router.post("/api/login/verify")
async def login_verify(request: Request):
    body = await request.json()
    credential = body.get("credential")
    if not credential:
        raise HTTPException(status_code=400, detail="invalid request")

    expected_challenge_b64 = request.session.pop("auth_challenge", None)
    issued_at = request.session.pop("auth_challenge_issued_at", None)
    if not expected_challenge_b64 or not issued_at:
        raise HTTPException(status_code=400, detail="login expired (start over)")
    if int(time.time()) - int(issued_at) > CHALLENGE_TTL_SECONDS:
        raise HTTPException(status_code=400, detail="login expired (start over)")

    try:
        credential_id_bytes = base64url_to_bytes(credential["id"])
    except Exception:
        raise HTTPException(status_code=400, detail="webauthn verification failed")

    cred_hash = crypto_store.sha256(credential_id_bytes)
    cred_row = db.find_credential_by_hash(cred_hash)
    if not cred_row:
        raise HTTPException(status_code=400, detail="webauthn verification failed")

    public_key = crypto_store.decrypt_public_key(cred_row)

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(expected_challenge_b64),
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=public_key,
            credential_current_sign_count=int(cred_row["sign_count"]),
            require_user_verification=True,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="webauthn verification failed")

    crypto_store.update_sign_count(
        cred_hash=cred_hash,
        new_sign_count=verification.new_sign_count,
        device_type=getattr(verification, "credential_device_type", None),
        backed_up=bool(getattr(verification, "credential_backed_up", False)),
    )

    username = request.session.get("auth_username", "unknown")
    request.session["user"] = {"username": username}
    return {"verified": True}