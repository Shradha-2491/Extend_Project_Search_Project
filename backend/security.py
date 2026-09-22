"""Centralized, reusable security controls shared by the web routes, the JSON
REST API, and (indirectly, via the API) the mobile app. Every RBAC check,
token operation, and piece of crypto in this project goes through here so
there is exactly one place to audit or fix -- see docs/doc-pdf/owasp-control-table.pdf
for the mapping of each control below to the OWASP risks it addresses.
"""
import base64
import hashlib
import json
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt as pyjwt
from cryptography.fernet import Fernet, InvalidToken
from flask import request, session, abort, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

import config
import db

# ---------------------------------------------------------------------------
# Password hashing (OWASP A02 - Cryptographic Failures)
# ---------------------------------------------------------------------------

def hash_password(plaintext: str) -> str:
    return generate_password_hash(plaintext)


def verify_password(hashed: str, plaintext: str) -> bool:
    return bool(hashed) and check_password_hash(hashed, plaintext)


# ---------------------------------------------------------------------------
# Encryption at rest for MFA secrets (OWASP A02 - Cryptographic Failures)
# ---------------------------------------------------------------------------

def _fernet():
    key = config.LAB_ENC_KEY
    if not key:
        # Deterministic-but-process-local fallback so the lab still runs
        # without extra setup; production deployments MUST set LAB_ENC_KEY.
        key = base64.urlsafe_b64encode(hashlib.sha256(config.LAB_SECRET_KEY.encode()).digest())
    elif isinstance(key, str):
        key = key.encode()
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(token: str) -> str | None:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return None


# ---------------------------------------------------------------------------
# CSRF (synchronizer token pattern) -- Web interface only (OWASP A01/CSRF)
# ---------------------------------------------------------------------------

def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def csrf_protect(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if request.method == "POST":
            expected = session.get("_csrf_token")
            submitted = request.form.get("csrf_token", "")
            if not expected or not submitted or not secrets.compare_digest(expected, submitted):
                db.log_event("csrf_failed", path=request.path, username=session.get("username"))
                abort(403, description="CSRF validation failed. Please retry from the form.")
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Session-based RBAC -- Web interface (OWASP A01 - Broken Access Control)
# ---------------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            return abort(401)
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                db.log_event(
                    "access_denied",
                    path=request.path,
                    username=session.get("username"),
                    required_roles=list(roles),
                )
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------------------
# JWT bearer auth -- API / Mobile interfaces (OWASP A01, A07)
# ---------------------------------------------------------------------------

def _now():
    return datetime.now(timezone.utc)


def issue_access_token(user_row, stage="full"):
    """stage='pending_mfa' issues a narrow token that only the MFA-verify
    endpoint accepts, so a password-only credential can never reach a
    protected resource without completing the second factor."""
    now = _now()
    payload = {
        "iss": config.JWT_ISSUER,
        "sub": str(user_row["id"]),
        "username": user_row["username"],
        "role": user_row["role"],
        "stage": stage,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(
            seconds=config.JWT_PENDING_MFA_TTL_SECONDS if stage == "pending_mfa"
            else config.JWT_ACCESS_TTL_SECONDS
        )).timestamp()),
    }
    return pyjwt.encode(payload, config.LAB_SECRET_KEY, algorithm="HS256")


def issue_refresh_token(user_row):
    jti = secrets.token_urlsafe(32)
    now = _now()
    expires_at = now + timedelta(seconds=config.JWT_REFRESH_TTL_SECONDS)
    con = db.connect()
    con.execute(
        "INSERT INTO refresh_tokens(jti, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (jti, user_row["id"], expires_at.isoformat(), now.isoformat()),
    )
    con.commit()
    con.close()
    payload = {
        "iss": config.JWT_ISSUER,
        "sub": str(user_row["id"]),
        "jti": jti,
        "typ": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    return pyjwt.encode(payload, config.LAB_SECRET_KEY, algorithm="HS256")


def decode_token(token):
    try:
        return pyjwt.decode(token, config.LAB_SECRET_KEY, algorithms=["HS256"], issuer=config.JWT_ISSUER)
    except pyjwt.PyJWTError:
        return None


def rotate_refresh_token(token):
    """Verify+revoke the presented refresh token and issue a fresh access +
    refresh pair. Rotation means a stolen-and-replayed refresh token is only
    usable once before the legitimate client's next refresh invalidates it,
    which is detectable (both attacker and victim can no longer refresh)."""
    claims = decode_token(token)
    if not claims or claims.get("typ") != "refresh":
        return None
    con = db.connect()
    row = con.execute(
        "SELECT * FROM refresh_tokens WHERE jti = ? AND user_id = ?",
        (claims["jti"], int(claims["sub"])),
    ).fetchone()
    if not row or row["revoked"]:
        con.close()
        return None
    if datetime.fromisoformat(row["expires_at"]) < _now():
        con.close()
        return None
    user = con.execute("SELECT * FROM users WHERE id = ?", (claims["sub"],)).fetchone()
    if not user or not user["active"]:
        con.close()
        return None
    con.execute("UPDATE refresh_tokens SET revoked = 1 WHERE jti = ?", (claims["jti"],))
    con.commit()
    con.close()
    return {
        "access_token": issue_access_token(user),
        "refresh_token": issue_refresh_token(user),
    }


def revoke_refresh_token(token):
    claims = decode_token(token)
    if not claims or claims.get("typ") != "refresh":
        return
    con = db.connect()
    con.execute("UPDATE refresh_tokens SET revoked = 1 WHERE jti = ?", (claims["jti"],))
    con.commit()
    con.close()


def _extract_bearer_claims(required_stage="full"):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    claims = decode_token(auth[len("Bearer "):])
    if not claims or claims.get("stage") != required_stage or claims.get("typ") == "refresh":
        return None
    return claims


def api_auth_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        claims = _extract_bearer_claims("full")
        if not claims:
            return jsonify(error="unauthorized"), 401
        g.user_claims = claims
        return view(*args, **kwargs)
    return wrapped


def api_pending_mfa_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        claims = _extract_bearer_claims("pending_mfa")
        if not claims:
            return jsonify(error="unauthorized"), 401
        g.user_claims = claims
        return view(*args, **kwargs)
    return wrapped


def api_role_required(*roles):
    def decorator(view):
        @wraps(view)
        @api_auth_required
        def wrapped(*args, **kwargs):
            if g.user_claims["role"] not in roles:
                db.log_event(
                    "access_denied",
                    path=request.path,
                    username=g.user_claims.get("username"),
                    required_roles=list(roles),
                )
                return jsonify(error="forbidden"), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------------------
# Google Sign-In identity validation -- shared by Web callback and Mobile
# endpoint (OWASP A07 - Identification & Authentication Failures). Both
# interfaces MUST call this single function so "is the email verified by
# Google" is answered in exactly one, fail-closed place.
# ---------------------------------------------------------------------------

class GoogleIdentityError(Exception):
    pass


def validate_google_userinfo(userinfo: dict) -> str:
    """Returns the normalized, lower-cased email or raises GoogleIdentityError.
    Fails CLOSED: a missing/absent email_verified claim is treated as NOT
    verified (the previous implementation defaulted to trusting it, which is
    the bug this function exists to fix)."""
    email = (userinfo or {}).get("email")
    if not email:
        raise GoogleIdentityError("no_email")
    if userinfo.get("email_verified") is not True:
        raise GoogleIdentityError("email_not_verified")
    return email.lower()


def verify_google_id_token_mobile(id_token: str) -> dict:
    """Independently verifies a raw id_token presented by the mobile app --
    signature, issuer, expiry, and audience (must equal the mobile-only OAuth
    client id) are all checked against Google's current public keys. Never
    trust client-asserted claims without this."""
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests

    if not config.GOOGLE_CLIENT_ID_MOBILE:
        raise GoogleIdentityError("mobile_google_not_configured")
    try:
        claims = google_id_token.verify_oauth2_token(
            id_token, google_requests.Request(), config.GOOGLE_CLIENT_ID_MOBILE
        )
    except ValueError as e:
        logging.warning("mobile google id_token rejected: %s", e)
        raise GoogleIdentityError("invalid_id_token")
    if claims.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        raise GoogleIdentityError("invalid_issuer")
    return claims


# ---------------------------------------------------------------------------
# Idempotency for price-sensitive endpoints (OWASP A04 - Insecure Design /
# race-condition & duplicate-submission protection)
# ---------------------------------------------------------------------------

def idempotency_replay(endpoint: str):
    """Returns a cached (status, body) tuple if this Idempotency-Key was
    already applied for this endpoint, else None."""
    key = request.headers.get("Idempotency-Key")
    if not key:
        return "missing_key", None
    con = db.connect()
    row = con.execute(
        "SELECT response_status, response_body FROM idempotency_keys "
        "WHERE idem_key = ? AND endpoint = ?",
        (key, endpoint),
    ).fetchone()
    con.close()
    if row:
        return key, (row["response_status"], json.loads(row["response_body"]))
    return key, None


def idempotency_store(con, endpoint: str, key: str, status: int, body: dict):
    """Must be called on the SAME connection/transaction that performed the
    state change, using INSERT OR IGNORE against the UNIQUE(idem_key,
    endpoint) constraint so that under real concurrent requests only one
    writer's row wins and the other observes 0 affected rows."""
    con.execute(
        "INSERT OR IGNORE INTO idempotency_keys(idem_key, endpoint, response_status, "
        "response_body, created_at) VALUES (?, ?, ?, ?, ?)",
        (key, endpoint, status, json.dumps(body), datetime.now(timezone.utc).isoformat()),
    )


# ---------------------------------------------------------------------------
# Input validation helpers (OWASP A03 - Injection / A04 - Insecure Design)
# ---------------------------------------------------------------------------

def validate_price(value) -> float:
    try:
        price = float(value)
    except (TypeError, ValueError):
        raise ValueError("price must be a number")
    if price < 0 or price > 10_000_000:
        raise ValueError("price out of allowed range")
    return round(price, 2)


def validate_stock(value) -> int:
    try:
        stock = int(value)
    except (TypeError, ValueError):
        raise ValueError("stock must be an integer")
    if stock < 0 or stock > 10_000_000:
        raise ValueError("stock out of allowed range")
    return stock


def validate_role(value) -> str:
    if value not in ("customer", "vendor", "admin"):
        raise ValueError("invalid role")
    return value
