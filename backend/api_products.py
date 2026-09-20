"""JSON REST product endpoints under /api/v1/products -- the Mobile app's
only way to reach product data. RBAC and role-scoped search reuse the exact
same security.api_role_required / products.search functions the Web UI uses."""
from flask import Blueprint, request, jsonify, g

import db
import products
import security
from extensions import limiter

bp = Blueprint("api_products", __name__, url_prefix="/api/v1/products")


def _actor():
    claims = g.user_claims
    return {"id": int(claims["sub"]), "username": claims["username"], "role": claims["role"]}


@bp.get("")
@security.api_auth_required
@limiter.limit("60 per minute")
def list_products():
    actor = _actor()
    term = request.args.get("q", "")
    return jsonify(results=products.search(actor["role"], actor["id"], term))


@bp.get("/<int:product_id>")
@security.api_auth_required
def get_product(product_id):
    actor = _actor()
    row = products.get_one(actor["role"], actor["id"], product_id)
    if not row:
        return jsonify(error="not_found"), 404
    return jsonify(row)


@bp.post("")
@security.api_role_required("vendor", "admin")
@limiter.limit("30 per minute")
def create_product():
    actor = _actor()
    data = request.get_json(silent=True) or {}
    try:
        price = security.validate_price(data.get("price"))
        stock = security.validate_stock(data.get("stock", 0))
        cost = security.validate_price(data.get("cost", 0))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    name = (data.get("name") or "").strip()
    category = (data.get("category") or "").strip()
    if not name or not category:
        return jsonify(error="name and category are required"), 400

    con = db.connect()
    row = con.execute("SELECT * FROM users WHERE id = ?", (actor["id"],)).fetchone()
    con.close()
    new_id = products.create_product(row, name, category, price, cost, stock)
    return jsonify(id=new_id), 201


@bp.patch("/<int:product_id>")
@security.api_role_required("vendor", "admin")
@limiter.limit("30 per minute")
def patch_product(product_id):
    actor = _actor()
    data = request.get_json(silent=True) or {}
    try:
        ok, err = products.update_product_fields(
            actor, product_id,
            name=data.get("name"), category=data.get("category"),
            stock=data.get("stock"), active=data.get("active"),
        )
    except ValueError as e:
        return jsonify(error=str(e)), 400
    if not ok:
        return jsonify(error=err), 404 if err == "not_found_or_forbidden" else 400
    return jsonify(message="updated")


@bp.patch("/<int:product_id>/price")
@security.api_role_required("vendor", "admin")
@limiter.limit("20 per minute")
def patch_price(product_id):
    """Price-sensitive endpoint: requires the client's last-known `version`
    (optimistic concurrency) and a unique `Idempotency-Key` header (duplicate
    request protection). See products.update_price for the concurrency-safe
    implementation and docs/test-evidence/ for the concurrent-request proof."""
    actor = _actor()
    data = request.get_json(silent=True) or {}
    idem_key = request.headers.get("Idempotency-Key")
    body, err, status = products.update_price(
        actor, product_id, data.get("price"), data.get("version"), idem_key
    )
    return jsonify(body), status


@bp.delete("/<int:product_id>")
@security.api_role_required("vendor", "admin")
def delete_product(product_id):
    actor = _actor()
    if not products.soft_delete(actor, product_id):
        return jsonify(error="not_found_or_forbidden"), 404
    return jsonify(message="removed")
