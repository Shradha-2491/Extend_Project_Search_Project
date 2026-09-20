"""Auth flows shared verbatim by the Web routes (web.py) and the JSON REST
API (api_auth.py) -- registration, password login with lockout, TOTP MFA
enrollment/verification, Google provisioning, and password reset. Keeping
this logic in one place is what lets both interfaces enforce identical
policy (e.g. MFA is mandatory no matter which door you came in)."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import config
import db
import mail
import mfa
import security


class AuthError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _now():
    return datetime.now(timezone.utc)


def _row_to_dict(row):
    return {k: row[k] for k in row.keys()}


def register_user(username: str, email: str, password: str):
    username = (username or "").strip()
    email = (email or "").strip().lower()
    if len(username) < 3 or len(password) < 10:
        raise AuthError("weak_credentials")
    if "@" not in email:
        raise AuthError("invalid_email")

    con = db.connect()
    try:
        con.execute(
            "INSERT INTO users(username, email, password, role, auth_provider, created_at) "
            "VALUES (?, ?, ?, 'customer', 'local', ?)",
            (username, email, security.hash_password(password), _now().isoformat()),
        )
        con.commit()
    except db.sqlite3.IntegrityError:
        raise AuthError("username_or_email_taken")
    finally:
        row = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        con.close()
    db.log_event("user_registered", username=username, role="customer")
    return _row_to_dict(row)


def authenticate_password(username: str, password: str):
    con = db.connect()
    row = con.execute(
        "SELECT * FROM users WHERE username = ? AND auth_provider = 'local'", (username,)
    ).fetchone()

    if row and row["locked_until"] and datetime.fromisoformat(row["locked_until"]) > _now():
        con.close()
        db.log_event("login_failed", username=username, reason="locked")
        raise AuthError("account_locked")

    ok = row is not None and row["active"] and security.verify_password(row["password"], password)
    if not ok:
        if row:
            failed = row["failed_logins"] + 1
            lock_until = None
            if failed >= config.LOGIN_MAX_FAILED_ATTEMPTS:
                lock_until = (_now() + timedelta(seconds=config.LOGIN_LOCKOUT_SECONDS)).isoformat()
                failed = 0
            con.execute(
                "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                (failed, lock_until, row["id"]),
            )
            con.commit()
        con.close()
        db.log_event("login_failed", username=username, provider="local")
        raise AuthError("invalid_credentials")

    con.execute(
        "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (row["id"],)
    )
    con.commit()
    con.close()
    db.log_event("login_success", username=row["username"], role=row["role"], provider="local")
    return _row_to_dict(row)


def provision_or_get_google_user(email: str):
    """Shared by the Web callback and the Mobile endpoint -- both call
    security.validate_google_userinfo()/verify_google_id_token_mobile() first
    to establish `email` is Google-verified, then land here for the identical
    account-provisioning / provider-conflict policy."""
    con = db.connect()
    row = con.execute("SELECT * FROM users WHERE email = ? OR username = ?", (email, email)).fetchone()

    if row is not None and row["auth_provider"] != "google":
        con.close()
        db.log_event("login_failed", provider="google", reason="account_provider_conflict", username=email)
        raise AuthError("account_provider_conflict")

    if row is None:
        role = "admin" if email in config.ADMIN_EMAILS else "customer"
        con.execute(
            "INSERT INTO users(username, email, password, role, auth_provider, created_at) "
            "VALUES (?, ?, NULL, ?, 'google', ?)",
            (email, email, role, _now().isoformat()),
        )
        con.commit()
        row = con.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        db.log_event("user_provisioned", username=email, role=role, provider="google")
    con.close()
    db.log_event("login_success", username=row["username"], role=row["role"], provider="google")
    return _row_to_dict(row)


def start_mfa_enrollment(user_row):
    secret = mfa.generate_secret()
    con = db.connect()
    con.execute(
        "UPDATE users SET mfa_secret_enc = ? WHERE id = ?",
        (security.encrypt_secret(secret), user_row["id"]),
    )
    con.commit()
    con.close()
    uri = mfa.provisioning_uri(secret, user_row["email"] or user_row["username"])
    return secret, uri


def confirm_mfa_enrollment(user_id: int, code: str) -> bool:
    con = db.connect()
    row = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row or not row["mfa_secret_enc"]:
        con.close()
        return False
    secret = security.decrypt_secret(row["mfa_secret_enc"])
    if not mfa.verify_code(secret, code):
        con.close()
        db.log_event("mfa_enroll_failed", username=row["username"])
        return False
    con.execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?", (user_id,))
    con.commit()
    con.close()
    db.log_event("mfa_enrolled", username=row["username"])
    return True


def verify_mfa_login(user_id: int, code: str) -> bool:
    con = db.connect()
    row = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        con.close()
        return False

    if row["mfa_locked_until"] and datetime.fromisoformat(row["mfa_locked_until"]) > _now():
        con.close()
        db.log_event("mfa_verify_failed", username=row["username"], reason="locked")
        return False

    secret = security.decrypt_secret(row["mfa_secret_enc"]) if row["mfa_secret_enc"] else None
    if secret and mfa.verify_code(secret, code):
        con.execute(
            "UPDATE users SET mfa_failed_attempts = 0, mfa_locked_until = NULL WHERE id = ?",
            (user_id,),
        )
        con.commit()
        con.close()
        db.log_event("mfa_verify_success", username=row["username"])
        return True

    attempts = row["mfa_failed_attempts"] + 1
    lock_until = None
    if attempts >= config.MFA_MAX_FAILED_ATTEMPTS:
        lock_until = (_now() + timedelta(seconds=config.MFA_LOCKOUT_SECONDS)).isoformat()
        attempts = 0
    con.execute(
        "UPDATE users SET mfa_failed_attempts = ?, mfa_locked_until = ? WHERE id = ?",
        (attempts, lock_until, user_id),
    )
    con.commit()
    con.close()
    db.log_event("mfa_verify_failed", username=row["username"])
    return False


def request_password_reset(identifier: str):
    """Always behaves the same way externally regardless of whether the
    account exists, to avoid user-enumeration (OWASP A07)."""
    con = db.connect()
    row = con.execute(
        "SELECT * FROM users WHERE (username = ? OR email = ?) AND auth_provider = 'local'",
        (identifier, identifier),
    ).fetchone()
    if row:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        expires = (_now() + timedelta(seconds=config.PASSWORD_RESET_TTL_SECONDS)).isoformat()
        con.execute(
            "UPDATE users SET reset_token_hash = ?, reset_expires = ? WHERE id = ?",
            (token_hash, expires, row["id"]),
        )
        con.commit()
        mail.send_mail(
            row["email"] or row["username"],
            "Password reset",
            f"Reset token (valid 15 minutes): {token}\n"
            "Submit this with your new password at /password-reset/confirm.",
        )
        db.log_event("password_reset_requested", username=row["username"])
    con.close()


def confirm_password_reset(token: str, new_password: str):
    if len(new_password) < 10:
        raise AuthError("weak_password")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    con = db.connect()
    row = con.execute(
        "SELECT * FROM users WHERE reset_token_hash = ?", (token_hash,)
    ).fetchone()
    if not row or not row["reset_expires"] or datetime.fromisoformat(row["reset_expires"]) < _now():
        con.close()
        raise AuthError("invalid_or_expired_token")
    con.execute(
        "UPDATE users SET password = ?, reset_token_hash = NULL, reset_expires = NULL, "
        "failed_logins = 0, locked_until = NULL WHERE id = ?",
        (security.hash_password(new_password), row["id"]),
    )
    con.commit()
    con.close()
    db.log_event("password_reset_completed", username=row["username"])
