"""JSON REST auth endpoints under /api/v1/auth -- used by the Mobile app and
any other API client. Every rule enforced here (MFA mandatory, lockouts,
Google email_verified) is the exact same rule the Web routes enforce,
because both call into auth_service.py / security.py rather than
re-implementing policy."""
from flask import Blueprint, request, jsonify, g

import auth_service
import db
import mfa as mfa_mod
import security
from extensions import limiter

bp = Blueprint("api_auth", __name__, url_prefix="/api/v1/auth")


def _user_row(user_id):
    con = db.connect()
    row = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    con.close()
    return row


@bp.post("/register")
@limiter.limit("10 per hour")
def register():
    data = request.get_json(silent=True) or {}
    try:
        auth_service.register_user(data.get("username", ""), data.get("email", ""), data.get("password", ""))
    except auth_service.AuthError as e:
        return jsonify(error=e.code), 400
    return jsonify(message="registered, please log in and enroll MFA"), 201


@bp.post("/login")
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True) or {}
    try:
        user = auth_service.authenticate_password(data.get("username", ""), data.get("password", ""))
    except auth_service.AuthError as e:
        return jsonify(error=e.code), 401
    pending = security.issue_access_token(user, stage="pending_mfa")
    return jsonify(
        mfa_required=True,
        mfa_enrolled=bool(user["mfa_enabled"]),
        pending_token=pending,
    )


@bp.post("/google/mobile")
@limiter.limit("15 per minute")
def google_mobile():
    """Mobile Google Sign-In: the app authenticates with Google itself via
    Credential Manager and hands us only the resulting id_token. We
    independently verify it against Google's public keys before trusting
    anything in it -- see security.verify_google_id_token_mobile /
    validate_google_userinfo."""
    data = request.get_json(silent=True) or {}
    id_token = data.get("id_token", "")
    try:
        claims = security.verify_google_id_token_mobile(id_token)
        email = security.validate_google_userinfo(claims)
        user = auth_service.provision_or_get_google_user(email)
    except security.GoogleIdentityError as e:
        return jsonify(error=str(e)), 401
    except auth_service.AuthError as e:
        return jsonify(error=e.code), 409
    pending = security.issue_access_token(user, stage="pending_mfa")
    return jsonify(mfa_required=True, mfa_enrolled=bool(user["mfa_enabled"]), pending_token=pending)


@bp.post("/mfa/enroll")
@security.api_pending_mfa_required
@limiter.limit("10 per minute")
def mfa_enroll():
    row = _user_row(int(g.user_claims["sub"]))
    if row["mfa_enabled"]:
        return jsonify(error="already_enrolled"), 400
    secret, uri = auth_service.start_mfa_enrollment(row)
    return jsonify(secret=secret, otpauth_uri=uri, qr_data_uri=mfa_mod.qr_data_uri(uri))


@bp.post("/mfa/verify")
@security.api_pending_mfa_required
@limiter.limit("10 per minute")
def mfa_verify():
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")
    user_id = int(g.user_claims["sub"])
    row = _user_row(user_id)

    if not row["mfa_enabled"]:
        ok = auth_service.confirm_mfa_enrollment(user_id, code)
    else:
        ok = auth_service.verify_mfa_login(user_id, code)

    if not ok:
        return jsonify(error="invalid_code"), 401

    row = _user_row(user_id)
    return jsonify(
        access_token=security.issue_access_token(row),
        refresh_token=security.issue_refresh_token(row),
        role=row["role"],
        username=row["username"],
    )


@bp.post("/refresh")
@limiter.limit("30 per minute")
def refresh():
    data = request.get_json(silent=True) or {}
    result = security.rotate_refresh_token(data.get("refresh_token", ""))
    if not result:
        return jsonify(error="invalid_refresh_token"), 401
    return jsonify(**result)


@bp.post("/logout")
def logout():
    data = request.get_json(silent=True) or {}
    security.revoke_refresh_token(data.get("refresh_token", ""))
    return jsonify(message="logged out")


@bp.post("/password-reset/request")
@limiter.limit("5 per hour")
def password_reset_request():
    data = request.get_json(silent=True) or {}
    auth_service.request_password_reset(data.get("identifier", ""))
    return jsonify(message="if an account exists, reset instructions were sent")


@bp.post("/password-reset/confirm")
@limiter.limit("10 per hour")
def password_reset_confirm():
    data = request.get_json(silent=True) or {}
    try:
        auth_service.confirm_password_reset(data.get("token", ""), data.get("new_password", ""))
    except auth_service.AuthError as e:
        return jsonify(error=e.code), 400
    return jsonify(message="password updated")
