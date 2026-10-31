import logging
import os
import re
import smtplib
from typing import Annotated, Any, Optional
from fastapi.middleware.cors import CORSMiddleware

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

try:
    from . import database
    from .email_service import SMTPConfigurationError, send_otp_email
except ImportError:
    import database
    from email_service import SMTPConfigurationError, send_otp_email


app = FastAPI(title="ArmorCode Security & IP Watermarking API", version="2.1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # This allows your frontend to connect during local development
    allow_credentials=True,
    allow_methods=["*"], # This fixes the OPTIONS 405 error
    allow_headers=["*"],
)
logger = logging.getLogger(__name__)
ZERO_WIDTH_CHARS = ("\u200b", "\u200c", "\u200d")
FRONTEND_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "frontend")
)


def mask_email(email: str) -> str:
    local, separator, domain = email.partition("@")
    if not separator:
        return "hidden"
    visible = local[0] + "***" + (local[-1] if len(local) > 1 else "")
    return f"{visible}@{domain}"


def parse_signature_and_owner(payload: str) -> tuple[str, Optional[str]]:
    match = re.match(
        r"^(.*?)\s*<([^@\s]+@[^@\s]+\.[^@\s]+)>$", payload.strip()
    )
    if match:
        return match.group(1).strip(), match.group(2).strip().lower()
    return payload.strip(), None


def extract_zw_author_and_owner(text: str) -> tuple[Optional[str], Optional[str]]:
    stream = "".join(ch for ch in text if ch in ZERO_WIDTH_CHARS)
    segments = [part for part in stream.split("\u200d") if part]
    for segment in segments:
        bits = "".join("0" if ch == "\u200b" else "1" for ch in segment)
        usable_length = len(bits) - (len(bits) % 8)
        if usable_length < 16:
            continue
        data = bytes(
            int(bits[index : index + 8], 2)
            for index in range(0, usable_length, 8)
        )
        payloads = [data]
        if len(data) >= 2:
            checked_payload, checksum = data[:-1], data[-1]
            crc = 0x5A
            for byte in checked_payload:
                crc = ((crc << 1) | (crc >> 7)) & 0xFF
                crc ^= byte
            if crc == checksum:
                payloads = [checked_payload]
        for payload in payloads:
            try:
                signature, email = parse_signature_and_owner(
                    payload.decode("utf-8")
                )
            except UnicodeDecodeError:
                continue
            if signature and email:
                return signature, email
    return None, None


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=256)
    default_signature: Optional[str] = Field(default=None, max_length=48)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class CodeRequest(BaseModel):
    code_text: str = Field(min_length=1, max_length=1_000_000)


class SignOtpRequest(CodeRequest):
    signature: str = Field(min_length=1, max_length=48)
    otp_code: Optional[str] = Field(
        default=None, min_length=6, max_length=6, pattern=r"^[0-9]{6}$"
    )


class ReassignOtpRequest(SignOtpRequest):
    otp_code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


def current_user_from_authorization(
    authorization: Optional[str] = Header(default=None),
) -> dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Sign in to continue.")
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="Invalid authentication token.")
    user = database.get_user_for_session(token.strip())
    if not user:
        raise HTTPException(status_code=401, detail="Session expired. Sign in again.")
    return user


CurrentUser = Annotated[dict[str, Any], Depends(current_user_from_authorization)]


def issue_otp(email: str, action: str, code_hash: str, signature: str) -> None:
    try:
        otp = database.create_and_store_otp(
            email=email,
            action=action,
            code_hash=code_hash,
            target_signature=signature,
        )
    except ValueError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc

    try:
        send_otp_email(email, otp, action=action)
    except (OSError, RuntimeError, smtplib.SMTPException, ValueError) as exc:
        database.invalidate_otp(email, action, code_hash)
        logger.exception("Could not dispatch %s OTP to %s", action, mask_email(email))
        if isinstance(exc, SMTPConfigurationError):
            detail = (
                "Email delivery is not configured. Copy backend/.env.example to "
                "backend/.env, enter your SMTP settings, and restart the server."
            )
        elif isinstance(exc, ValueError):
            detail = (
                "SMTP settings are invalid. Check SMTP_PORT and SMTP_TIMEOUT in "
                "backend/.env, then restart the server."
            )
        else:
            detail = (
                "SMTP delivery failed. Check your provider settings and credentials "
                "in backend/.env, then restart the server."
            )
        raise HTTPException(
            status_code=503,
            detail=detail,
        ) from exc


def get_original_owner(code_hash: str, code_text: str) -> tuple[Optional[str], Optional[str]]:
    record = database.get_code_owner(code_hash)
    embedded_signature, embedded_email = extract_zw_author_and_owner(code_text)
    if record:
        return record["owner_email"].lower(), record["author_signature"]
    return embedded_email, embedded_signature


def clean_code(code_text: str) -> str:
    return "".join(ch for ch in code_text if ch not in ZERO_WIDTH_CHARS)


def validated_signature(signature: str) -> str:
    value = signature.strip()
    if not value:
        raise HTTPException(status_code=400, detail="Signature cannot be blank.")
    return value


def safe_history(history: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "previous_owner": mask_email(entry.get("previous_owner", "")),
            "new_owner": mask_email(entry.get("new_owner", "")),
            "reassigned_at": str(entry.get("reassigned_at", "")),
        }
        for entry in history
    ]


@app.post("/api/auth/register")
def register(req: RegisterRequest) -> dict[str, Any]:
    try:
        user = database.create_user(
            email=req.email,
            name=req.name,
            password=req.password,
            default_signature=req.default_signature,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    token = database.create_session(user["id"])
    return {"success": True, "user": user, "token": token}


@app.post("/api/auth/login")
def login(req: LoginRequest) -> dict[str, Any]:
    user = database.authenticate_user(req.email, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    token = database.create_session(user["id"])
    return {"success": True, "user": user, "token": token}


@app.get("/api/auth/me")
def get_me(user: CurrentUser) -> dict[str, Any]:
    return {"user": user}


@app.post("/api/auth/logout")
def logout(
    _user: CurrentUser,
    authorization: Optional[str] = Header(default=None),
) -> dict[str, bool]:
    if authorization:
        _, _, token = authorization.partition(" ")
        database.revoke_session(token.strip())
    return {"success": True}


@app.post("/api/code/check-owner")
def check_owner(req: CodeRequest, user: CurrentUser) -> dict[str, Any]:
    code_hash = database.compute_normalized_code_hash(req.code_text)
    record = database.get_code_owner(code_hash)
    embedded_signature, embedded_email = extract_zw_author_and_owner(req.code_text)
    original_email = record["owner_email"] if record else embedded_email
    original_signature = (
        record["author_signature"] if record else embedded_signature
    )
    reassignment = bool(
        original_email and original_email.lower() != user["email"].lower()
    )
    return {
        "code_hash": code_hash,
        "is_registered": record is not None or embedded_email is not None,
        "requires_reassignment": reassignment,
        "owner_email": (
            original_email
            if original_email and original_email.lower() == user["email"].lower()
            else None
        ),
        "masked_owner_email": mask_email(original_email) if original_email else None,
        "author_signature": original_signature,
        "has_zero_width_watermark": embedded_email is not None,
        "history": safe_history(record.get("history", [])) if record else [],
    }


@app.post("/api/otp/send-sign-otp")
def send_sign_otp(req: SignOtpRequest, user: CurrentUser) -> dict[str, Any]:
    code_hash = database.compute_normalized_code_hash(req.code_text)
    signature = validated_signature(req.signature)
    original_owner, original_signature = get_original_owner(code_hash, req.code_text)
    reassignment = bool(
        original_owner and original_owner.lower() != user["email"].lower()
    )

    issue_otp(user["email"], "sign", code_hash, signature)
    return {
        "success": True,
        "code_hash": code_hash,
        "requires_reassignment": reassignment,
        "masked_owner_email": mask_email(original_owner) if original_owner else None,
        "original_signature": original_signature,
    }


@app.post("/api/otp/verify-sign-otp")
def verify_sign_otp(req: SignOtpRequest, user: CurrentUser) -> dict[str, Any]:
    if req.otp_code is None:
        raise HTTPException(status_code=400, detail="Enter the email verification code.")
    code_hash = database.compute_normalized_code_hash(req.code_text)
    signature = validated_signature(req.signature)
    if not database.verify_stored_otp(
        user["email"], req.otp_code, "sign", code_hash, signature
    ):
        raise HTTPException(
            status_code=400, detail="Invalid or expired email verification code."
        )

    original_owner, original_signature = get_original_owner(code_hash, req.code_text)
    if original_owner and original_owner.lower() != user["email"].lower():
        return {
            "success": True,
            "verified": True,
            "requires_reassignment": True,
            "masked_owner_email": mask_email(original_owner),
            "original_signature": original_signature,
        }

    try:
        database.register_code_ownership(
            code_hash=code_hash,
            owner_email=user["email"],
            author_signature=signature,
            clean_code=clean_code(req.code_text),
            embedded_owner_email=original_owner,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    database.clear_otps_for_code(code_hash)
    return {
        "success": True,
        "verified": True,
        "requires_reassignment": False,
        "owner_email": user["email"],
        "author_signature": signature,
        "code_hash": code_hash,
    }


@app.post("/api/otp/send-reassign-otp")
def send_reassign_otp(req: SignOtpRequest, user: CurrentUser) -> dict[str, Any]:
    code_hash = database.compute_normalized_code_hash(req.code_text)
    signature = validated_signature(req.signature)
    if not database.has_verified_otp(
        user["email"], "sign", code_hash, signature
    ):
        raise HTTPException(
            status_code=403,
            detail="Verify your own email OTP before requesting owner authorization.",
        )

    original_owner, original_signature = get_original_owner(code_hash, req.code_text)
    if not original_owner:
        raise HTTPException(
            status_code=400,
            detail="Original owner could not be verified for this code.",
        )
    if original_owner.lower() == user["email"].lower():
        raise HTTPException(
            status_code=409,
            detail="This code is already registered to your account.",
        )

    issue_otp(original_owner, "reassign", code_hash, signature)
    return {
        "success": True,
        "code_hash": code_hash,
        "masked_owner_email": mask_email(original_owner),
        "original_signature": original_signature,
    }


@app.post("/api/otp/verify-reassign-otp")
def verify_reassign_otp(req: ReassignOtpRequest, user: CurrentUser) -> dict[str, Any]:
    code_hash = database.compute_normalized_code_hash(req.code_text)
    signature = validated_signature(req.signature)
    if not database.has_verified_otp(
        user["email"], "sign", code_hash, signature
    ):
        raise HTTPException(
            status_code=403,
            detail="Your account email verification is missing or expired.",
        )

    original_owner, _ = get_original_owner(code_hash, req.code_text)
    if not original_owner or original_owner.lower() == user["email"].lower():
        raise HTTPException(
            status_code=409,
            detail="The original owner has changed or no longer requires reassignment.",
        )
    if not database.verify_stored_otp(
        original_owner, req.otp_code, "reassign", code_hash, signature
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired original-owner authorization code.",
        )

    try:
        database.register_code_ownership(
            code_hash=code_hash,
            owner_email=user["email"],
            author_signature=signature,
            clean_code=clean_code(req.code_text),
            authorized_original_owner_email=original_owner,
            embedded_owner_email=original_owner,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    database.clear_otps_for_code(code_hash)
    return {
        "success": True,
        "verified": True,
        "new_owner_email": user["email"],
        "new_signature": signature,
        "code_hash": code_hash,
        "previous_owner": mask_email(original_owner),
    }


@app.get("/api/code/my-codes")
def my_codes(user: CurrentUser) -> dict[str, Any]:
    codes = database.get_user_registered_codes(user["email"])
    for code in codes:
        code["history"] = safe_history(code.get("history", []))
    return {
        "codes": codes,
    }


@app.get("/armorcode_cli.py", include_in_schema=False)
def get_cli_source() -> FileResponse:
    cli_path = os.path.join(os.path.dirname(__file__), "armorcode_cli.py")
    return FileResponse(cli_path, media_type="text/x-python")


if os.path.isdir(FRONTEND_PATH):
    app.mount("/", StaticFiles(directory=FRONTEND_PATH, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
