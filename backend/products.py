"""Product domain logic shared by the Web search page and the JSON REST API
(`GET /api/v1/products` and friends). Having exactly one function decide
which rows and which columns a role may see is what makes role-scoped search
a single reusable control instead of two independently-maintained copies
that could drift apart -- see docs/doc-pdf/owasp-control-table.pdf, OWASP A01."""
from datetime import datetime, timezone

import db
import security

CUSTOMER_FIELDS = ("id", "name", "category", "price")
VENDOR_FIELDS = ("id", "name", "category", "price", "cost", "stock", "active", "version")
ADMIN_FIELDS = (
    "id", "name", "category", "price", "cost", "stock", "active", "vendor_id",
    "version", "created_at", "updated_at", "created_by", "updated_by",
)


def visible_fields(role: str) -> tuple:
    if role == "admin":
        return ADMIN_FIELDS
    if role == "vendor":
        return VENDOR_FIELDS
    return CUSTOMER_FIELDS


def search(role: str, user_id: int, term: str, con=None):
    """One centralized query builder: customers only ever see active listings
    with public fields; vendors see their own inventory (any active state)
    plus cost/stock; admins see everything including audit fields."""
    owns_con = con is None
    con = con or db.connect()
    like_pattern = f"%{db.like_escape(term)}%"

    if role == "admin":
        sql = "SELECT * FROM products WHERE name LIKE ? ESCAPE '\\' ORDER BY id"
        params = (like_pattern,)
    elif role == "vendor":
        sql = (
            "SELECT * FROM products WHERE vendor_id = ? AND name LIKE ? ESCAPE '\\' ORDER BY id"
        )
        params = (user_id, like_pattern)
    else:
        sql = (
            "SELECT * FROM products WHERE active = 1 AND name LIKE ? ESCAPE '\\' ORDER BY id"
        )
        params = (like_pattern,)

    rows = con.execute(sql, params).fetchall()
    if owns_con:
        con.close()
    fields = visible_fields(role)
    return [{f: row[f] for f in fields} for row in rows]


def get_one(role: str, user_id: int, product_id: int):
    con = db.connect()
    row = con.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    con.close()
    if not row:
        return None
    if role == "customer" and not row["active"]:
        return None
    if role == "vendor" and row["vendor_id"] != user_id:
        return None
    fields = visible_fields(role)
    return {f: row[f] for f in fields}


def create_product(vendor_user, name, category, price, cost, stock):
    now = datetime.now(timezone.utc).isoformat()
    con = db.connect()
    cur = con.execute(
        "INSERT INTO products(name, category, price, cost, stock, active, vendor_id, "
        "version, created_at, updated_at, created_by, updated_by) "
        "VALUES (?, ?, ?, ?, ?, 1, ?, 1, ?, ?, ?, ?)",
        (name, category, price, cost, stock, vendor_user["id"], now, now,
         vendor_user["username"], vendor_user["username"]),
    )
    con.commit()
    new_id = cur.lastrowid
    con.close()
    db.log_event("product_created", by=vendor_user["username"], product_id=new_id, name=name)
    return new_id


def _owns_or_admin(row, actor):
    return actor["role"] == "admin" or (actor["role"] == "vendor" and row["vendor_id"] == actor["id"])


def update_product_fields(actor, product_id, name=None, category=None, stock=None, active=None):
    """Non-price mutable fields. Ownership is re-checked server-side on every
    call using the row just read -- the client-supplied vendor_id is never
    trusted (prevents IDOR / mass-assignment of another vendor's stock)."""
    con = db.connect()
    row = con.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if not row or not _owns_or_admin(row, actor):
        con.close()
        return None, "not_found_or_forbidden"

    updates, params = [], []
    if name is not None:
        updates.append("name = ?"); params.append(name)
    if category is not None:
        updates.append("category = ?"); params.append(category)
    if stock is not None:
        updates.append("stock = ?"); params.append(security.validate_stock(stock))
    if active is not None:
        updates.append("active = ?"); params.append(1 if active else 0)
    if not updates:
        con.close()
        return None, "no_fields"

    updates.append("updated_at = ?"); params.append(datetime.now(timezone.utc).isoformat())
    updates.append("updated_by = ?"); params.append(actor["username"])
    updates.append("version = version + 1")
    params.append(product_id)
    # `updates` only ever contains hardcoded "<column> = ?" fragments chosen
    # above from a fixed allowlist of column names -- never user-controlled
    # text -- and every actual value is still bound as a `?` parameter, so
    # this is not string-built SQL injection despite the f-string shape.
    # Bandit's B608 can't see that distinction; accepted below.
    con.execute(f"UPDATE products SET {', '.join(updates)} WHERE id = ?", params)  # nosec B608
    con.commit()
    con.close()
    db.log_event("product_updated", by=actor["username"], product_id=product_id)
    return True, None


PRICE_ENDPOINT = "patch_price"


def update_price(actor, product_id, new_price, expected_version, idem_key):
    """Price-sensitive mutation. Two independent protections compose here,
    both applied inside a single `BEGIN IMMEDIATE` transaction so SQLite's
    writer lock makes the whole check-then-act sequence atomic across real
    concurrent requests (not just logically correct in isolation):

    1. Idempotency-Key: the first request to hold the write lock for this
       key wins and its response is cached; any request (retry, double
       submit, or a genuinely concurrent duplicate) that arrives with the
       same key -- before or after the first commits -- gets the identical
       cached response instead of re-applying the price change.
    2. Optimistic concurrency (the `version` column): if the key is new, the
       UPDATE only matches rows still at `expected_version`; a racing writer
       that read a now-stale version gets a clean 409 instead of silently
       clobbering someone else's change.
    """
    import json as _json
    try:
        price = security.validate_price(new_price)
    except ValueError as e:
        return None, str(e), 400
    if not idem_key:
        return None, "Idempotency-Key header is required for price changes", 400

    now = datetime.now(timezone.utc).isoformat()
    con = db.connect()
    con.execute("BEGIN IMMEDIATE")
    try:
        cached = con.execute(
            "SELECT response_status, response_body FROM idempotency_keys "
            "WHERE idem_key = ? AND endpoint = ?",
            (idem_key, PRICE_ENDPOINT),
        ).fetchone()
        if cached:
            con.commit()
            body = _json.loads(cached["response_body"])
            return body, body.get("error"), cached["response_status"]

        row = con.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if not row:
            status, body = 404, {"error": "not_found"}
        elif not _owns_or_admin(row, actor):
            status, body = 403, {"error": "forbidden"}
        else:
            cur = con.execute(
                "UPDATE products SET price = ?, version = version + 1, updated_at = ?, "
                "updated_by = ? WHERE id = ? AND version = ?",
                (price, now, actor["username"], product_id, expected_version),
            )
            if cur.rowcount == 0:
                status, body = 409, {"error": "version_conflict"}
                db.log_event(
                    "price_update_conflict", by=actor["username"], product_id=product_id,
                    expected_version=expected_version,
                )
            else:
                updated = con.execute(
                    "SELECT * FROM products WHERE id = ?", (product_id,)
                ).fetchone()
                status = 200
                body = {f: updated[f] for f in visible_fields(actor["role"])}
                db.log_event(
                    "price_updated", by=actor["username"], product_id=product_id,
                    new_price=price, new_version=updated["version"], idem_key=idem_key,
                )

        con.execute(
            "INSERT INTO idempotency_keys(idem_key, endpoint, response_status, "
            "response_body, created_at) VALUES (?, ?, ?, ?, ?)",
            (idem_key, PRICE_ENDPOINT, status, _json.dumps(body), now),
        )
        con.commit()
        return body, body.get("error"), status
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def soft_delete(actor, product_id):
    con = db.connect()
    row = con.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if not row or not _owns_or_admin(row, actor):
        con.close()
        return False
    con.execute(
        "UPDATE products SET active = 0, version = version + 1, updated_at = ?, updated_by = ? "
        "WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), actor["username"], product_id),
    )
    con.commit()
    con.close()
    db.log_event("product_removed", by=actor["username"], product_id=product_id)
    return True
