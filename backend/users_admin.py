"""Admin-only user administration, called identically by the Web /admin/users
routes and the /api/v1/admin/users REST endpoints (OWASP A01 - only 'admin'
role reaches these, enforced centrally in security.py's decorators)."""
from datetime import datetime, timezone

import db
import security

PUBLIC_FIELDS = ("id", "username", "email", "role", "auth_provider", "active",
                  "mfa_enabled", "created_at")


def list_users():
    con = db.connect()
    rows = con.execute("SELECT * FROM users ORDER BY id").fetchall()
    con.close()
    return [{f: r[f] for f in PUBLIC_FIELDS} for r in rows]


def create_user(username, email, password, role, by):
    role = security.validate_role(role)
    username = (username or "").strip()
    email = (email or "").strip().lower()
    if len(username) < 3 or len(password) < 10:
        raise ValueError("weak_credentials")
    con = db.connect()
    try:
        con.execute(
            "INSERT INTO users(username, email, password, role, auth_provider, created_at) "
            "VALUES (?, ?, ?, ?, 'local', ?)",
            (username, email, security.hash_password(password), role,
             datetime.now(timezone.utc).isoformat()),
        )
        con.commit()
    except db.sqlite3.IntegrityError:
        raise ValueError("username_or_email_taken")
    new_id = con.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]
    con.close()
    db.log_event("user_created_by_admin", by=by, username=username, role=role)
    return new_id


def update_user(user_id, role=None, active=None, reset_mfa=False, by=None):
    con = db.connect()
    row = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        con.close()
        raise ValueError("not_found")

    updates, params = [], []
    if role is not None:
        updates.append("role = ?"); params.append(security.validate_role(role))
    if active is not None:
        updates.append("active = ?"); params.append(1 if active else 0)
    if reset_mfa:
        updates.append("mfa_enabled = 0"); updates.append("mfa_secret_enc = NULL")
    if not updates:
        con.close()
        raise ValueError("no_fields")

    params.append(user_id)
    # Same pattern/justification as products.update_product_fields: `updates`
    # is built only from a fixed set of hardcoded "<column> = ?"/"<column> =
    # <literal>" fragments above, never from user input, and every value is
    # still a bound `?` parameter.
    con.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)  # nosec B608
    con.commit()
    con.close()
    db.log_event("user_updated_by_admin", by=by, user_id=user_id, role=role, active=active,
                 reset_mfa=reset_mfa)


def deactivate_user(user_id, by):
    """Soft-delete: the account is deactivated (login blocked) rather than
    hard-deleted, preserving audit-log/product-ownership referential
    integrity and the historical record -- see threat-model.md."""
    con = db.connect()
    con.execute("UPDATE users SET active = 0 WHERE id = ?", (user_id,))
    con.commit()
    con.close()
    db.log_event("user_deactivated_by_admin", by=by, user_id=user_id)
