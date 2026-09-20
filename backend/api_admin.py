"""JSON REST user-administration endpoints, admin-only. Mirrors the Web
/admin/users routes exactly via the same security.api_role_required /
users_admin functions -- adding, removing (soft-delete/deactivate) and
updating users is restricted to admin on both interfaces identically."""
from flask import Blueprint, request, jsonify, g

import db
import security
import users_admin
from extensions import limiter

bp = Blueprint("api_admin", __name__, url_prefix="/api/v1/admin")


@bp.get("/users")
@security.api_role_required("admin")
def list_users():
    return jsonify(results=users_admin.list_users())


@bp.post("/users")
@security.api_role_required("admin")
@limiter.limit("20 per hour")
def create_user():
    data = request.get_json(silent=True) or {}
    try:
        new_id = users_admin.create_user(
            data.get("username", ""), data.get("email", ""),
            data.get("password", ""), data.get("role", "customer"),
            by=g.user_claims["username"],
        )
    except ValueError as e:
        return jsonify(error=str(e)), 400
    return jsonify(id=new_id), 201


@bp.patch("/users/<int:user_id>")
@security.api_role_required("admin")
def patch_user(user_id):
    data = request.get_json(silent=True) or {}
    try:
        users_admin.update_user(
            user_id, role=data.get("role"), active=data.get("active"),
            reset_mfa=data.get("reset_mfa", False), by=g.user_claims["username"],
        )
    except ValueError as e:
        return jsonify(error=str(e)), 400
    return jsonify(message="updated")


@bp.delete("/users/<int:user_id>")
@security.api_role_required("admin")
def delete_user(user_id):
    if str(user_id) == g.user_claims["sub"]:
        return jsonify(error="cannot_deactivate_self"), 400
    users_admin.deactivate_user(user_id, by=g.user_claims["username"])
    return jsonify(message="deactivated")


@bp.get("/audit-log")
@security.api_role_required("admin")
def audit_log():
    ok, problems = db.verify_log_integrity()
    return jsonify(integrity_ok=ok, problems=problems, entries=db.read_audit_log())
