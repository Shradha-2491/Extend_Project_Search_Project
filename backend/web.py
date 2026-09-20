"""Server-rendered Web interface for the extended app: registration, MFA-
enforced login (password and Google), role-scoped product search/CRUD, price
protection UI, password reset, and admin user management. Every control here
(RBAC, CSRF, rate limiting, audit logging) is imported from security.py /
auth_service.py / products.py / users_admin.py -- the same functions the
JSON API uses -- rather than being re-implemented for the Web path."""
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, session, redirect, url_for, abort

import auth_service
import config
import db
import mfa as mfa_mod
import products
import security
import templates
import users_admin

bp = Blueprint("web", __name__)


# ---------------------------------------------------------------------------
# Pending-MFA session helpers (shared by password login and Google login so
# neither path can grant a full session without completing MFA)
# ---------------------------------------------------------------------------

def _start_pending_mfa(user):
    session.clear()
    session["pending_mfa_user_id"] = user["id"]
    session["pending_mfa_started"] = datetime.now(timezone.utc).isoformat()
    session["pending_mfa_provider"] = user["auth_provider"]


def _pending_mfa_user():
    uid = session.get("pending_mfa_user_id")
    started = session.get("pending_mfa_started")
    if not uid or not started:
        return None
    age = datetime.now(timezone.utc) - datetime.fromisoformat(started)
    if age > timedelta(seconds=config.JWT_PENDING_MFA_TTL_SECONDS):
        session.clear()
        return None
    con = db.connect()
    row = con.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    con.close()
    return row


def _finalize_login(user_row):
    provider = session.get("pending_mfa_provider", user_row["auth_provider"])
    session.clear()
    session.permanent = True
    session["username"] = user_row["username"]
    session["role"] = user_row["role"]
    session["auth_provider"] = provider
    session["user_id"] = user_row["id"]


# ---------------------------------------------------------------------------
# Registration / password login / MFA
# ---------------------------------------------------------------------------

@bp.route("/register", methods=["GET", "POST"])
@security.csrf_protect
def register():
    ctx = {"error": None, "success": False}
    if request.method == "POST":
        try:
            auth_service.register_user(
                request.form.get("username", ""), request.form.get("email", ""),
                request.form.get("password", ""),
            )
            ctx["success"] = True
        except auth_service.AuthError as e:
            ctx["error"] = e.code
    return templates.render_page(templates.REGISTER_BODY, session_username=session.get("username"),
                                  session_role=session.get("role"), **ctx)


@bp.route("/login2", methods=["GET", "POST"])
@security.csrf_protect
def login2():
    error = None
    if request.method == "POST":
        try:
            user = auth_service.authenticate_password(
                request.form.get("username", ""), request.form.get("password", "")
            )
            _start_pending_mfa(user)
            if not user["mfa_enabled"]:
                return redirect(url_for("web.mfa_setup"))
            return redirect(url_for("web.mfa_verify"))
        except auth_service.AuthError as e:
            error = e.code
    return templates.render_page(templates.LOGIN2_BODY, session_username=session.get("username"),
                                  session_role=session.get("role"), error=error)


@bp.route("/mfa/setup", methods=["GET", "POST"])
@security.csrf_protect
def mfa_setup():
    user = _pending_mfa_user()
    if not user:
        return abort(401)
    if user["mfa_enabled"]:
        return redirect(url_for("web.mfa_verify"))

    if "mfa_setup_secret" not in session:
        secret, uri = auth_service.start_mfa_enrollment(user)
        session["mfa_setup_secret"] = secret
        session["mfa_setup_uri"] = uri
    else:
        uri = session["mfa_setup_uri"]

    error = None
    if request.method == "POST":
        if auth_service.confirm_mfa_enrollment(user["id"], request.form.get("code", "")):
            session.pop("mfa_setup_secret", None)
            session.pop("mfa_setup_uri", None)
            _finalize_login(user)
            return redirect(url_for("web.products_page"))
        error = "Invalid code, please try again."

    return templates.render_page(
        templates.MFA_SETUP_BODY, session_username=None, session_role=None,
        secret=session["mfa_setup_secret"], qr_data_uri=mfa_mod.qr_data_uri(uri), error=error,
    )


@bp.route("/mfa/verify", methods=["GET", "POST"])
@security.csrf_protect
def mfa_verify():
    user = _pending_mfa_user()
    if not user:
        return abort(401)

    error = None
    if request.method == "POST":
        if auth_service.verify_mfa_login(user["id"], request.form.get("code", "")):
            _finalize_login(user)
            return redirect(url_for("web.products_page"))
        error = "Invalid or expired code."

    return templates.render_page(
        templates.MFA_VERIFY_BODY, session_username=None, session_role=None, error=error
    )


# ---------------------------------------------------------------------------
# Google Sign-In (web) -- routes through the identical MFA gate as password
# login; email_verified is enforced by security.validate_google_userinfo.
# ---------------------------------------------------------------------------

@bp.route("/login/google/callback")
def google_callback_extended():
    """Registered here instead of app.py so the fixed, fail-closed
    email_verified check and the mandatory MFA gate apply to every Google
    sign-in, replacing the old callback in the legacy lab module."""
    from app import google_oauth

    if not google_oauth:
        abort(503, description="Google Sign-In is not configured on this server.")
    token = google_oauth.authorize_access_token()
    userinfo = token.get("userinfo") or {}
    try:
        email = security.validate_google_userinfo(userinfo)
        user = auth_service.provision_or_get_google_user(email)
    except security.GoogleIdentityError as e:
        db.log_event("login_failed", provider="google", reason=str(e))
        abort(401, description="Google did not confirm this account's email as verified.")
    except auth_service.AuthError:
        abort(409, description=(
            "An account with this email already exists using password login. "
            "Sign in with your password instead."
        ))
    _start_pending_mfa(user)
    if not user["mfa_enabled"]:
        return redirect(url_for("web.mfa_setup"))
    return redirect(url_for("web.mfa_verify"))


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------

@bp.route("/password-reset/request", methods=["GET", "POST"])
@security.csrf_protect
def password_reset_request():
    sent = False
    if request.method == "POST":
        auth_service.request_password_reset(request.form.get("identifier", ""))
        sent = True
    return templates.render_page(templates.PASSWORD_RESET_REQUEST_BODY, session_username=None,
                                  session_role=None, sent=sent)


@bp.route("/password-reset/confirm", methods=["GET", "POST"])
@security.csrf_protect
def password_reset_confirm():
    error, success = None, False
    if request.method == "POST":
        try:
            auth_service.confirm_password_reset(
                request.form.get("token", ""), request.form.get("new_password", "")
            )
            success = True
        except auth_service.AuthError as e:
            error = e.code
    return templates.render_page(
        templates.PASSWORD_RESET_CONFIRM_BODY, session_username=None, session_role=None,
        token=request.args.get("token", ""), error=error, success=success,
    )


# ---------------------------------------------------------------------------
# Products (role-scoped search + vendor/admin CRUD + price protection)
# ---------------------------------------------------------------------------

_SCOPE_NOTES = {
    "customer": "Showing only active listings with public fields.",
    "vendor": "Showing your own inventory, including cost and stock.",
    "admin": "Showing all products, including audit fields.",
}


@bp.route("/products")
@security.login_required
def products_page():
    role, uid = session["role"], session["user_id"]
    term = request.args.get("q", "")
    rows = products.search(role, uid, term)
    return templates.render_page(
        templates.PRODUCTS_BODY, session_username=session["username"], session_role=role,
        term=term, rows=rows, fields=list(products.visible_fields(role)),
        scope_note=_SCOPE_NOTES[role],
    )


@bp.route("/products/new", methods=["GET", "POST"])
@security.role_required("vendor", "admin")
@security.csrf_protect
def product_new():
    error = None
    if request.method == "POST":
        try:
            price = security.validate_price(request.form.get("price"))
            cost = security.validate_price(request.form.get("cost", 0))
            stock = security.validate_stock(request.form.get("stock", 0))
            name = request.form.get("name", "").strip()
            category = request.form.get("category", "").strip()
            if not name or not category:
                raise ValueError("name and category are required")
            con = db.connect()
            actor = con.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
            con.close()
            products.create_product(actor, name, category, price, cost, stock)
            return redirect(url_for("web.products_page"))
        except ValueError as e:
            error = str(e)
    return templates.render_page(templates.PRODUCT_NEW_BODY, session_username=session["username"],
                                  session_role=session["role"], error=error)


def _actor_dict():
    return {"id": session["user_id"], "username": session["username"], "role": session["role"]}


@bp.route("/products/<int:product_id>/edit", methods=["GET", "POST"])
@security.role_required("vendor", "admin")
@security.csrf_protect
def product_edit(product_id):
    product = products.get_one(session["role"], session["user_id"], product_id)
    if not product:
        abort(404)
    error, success = None, False
    if request.method == "POST":
        try:
            ok, err = products.update_product_fields(
                _actor_dict(), product_id,
                name=request.form.get("name"), category=request.form.get("category"),
                stock=request.form.get("stock"), active=request.form.get("active") == "1",
            )
            if not ok:
                error = err
            else:
                success = True
                product = products.get_one(session["role"], session["user_id"], product_id)
        except ValueError as e:
            error = str(e)
    return templates.render_page(templates.PRODUCT_EDIT_BODY, session_username=session["username"],
                                  session_role=session["role"], product=product, error=error,
                                  success=success)


@bp.route("/products/<int:product_id>/delete", methods=["POST"])
@security.role_required("vendor", "admin")
@security.csrf_protect
def product_delete(product_id):
    products.soft_delete(_actor_dict(), product_id)
    return redirect(url_for("web.products_page"))


@bp.route("/products/<int:product_id>/price", methods=["GET", "POST"])
@security.role_required("vendor", "admin")
@security.csrf_protect
def product_price(product_id):
    product = products.get_one(session["role"], session["user_id"], product_id)
    if not product:
        abort(404)
    error, success = None, False
    idempotency_key = secrets.token_hex(16)

    if request.method == "POST":
        body, err, status = products.update_price(
            _actor_dict(), product_id, request.form.get("price"),
            int(request.form.get("version", -1)), request.form.get("idempotency_key"),
        )
        if status == 200:
            success = True
            product = products.get_one(session["role"], session["user_id"], product_id)
            idempotency_key = secrets.token_hex(16)
        else:
            error = {
                "version_conflict": "Someone else changed this price first -- reload and retry.",
                "forbidden": "You do not own this product.",
                "not_found": "Product not found.",
            }.get(err, err)

    return templates.render_page(
        templates.PRODUCT_PRICE_BODY, session_username=session["username"],
        session_role=session["role"], product=product, error=error, success=success,
        idempotency_key=idempotency_key,
    )


# ---------------------------------------------------------------------------
# Admin user administration
# ---------------------------------------------------------------------------

@bp.route("/admin/users", methods=["GET", "POST"])
@security.role_required("admin")
@security.csrf_protect
def admin_users():
    error = None
    if request.method == "POST":
        try:
            users_admin.create_user(
                request.form.get("username", ""), request.form.get("email", ""),
                request.form.get("password", ""), request.form.get("role", "customer"),
                by=session["username"],
            )
        except ValueError as e:
            error = str(e)
    return templates.render_page(templates.ADMIN_USERS_BODY, session_username=session["username"],
                                  session_role=session["role"], users=users_admin.list_users(),
                                  error=error)


@bp.route("/admin/users/<int:user_id>", methods=["POST"])
@security.role_required("admin")
@security.csrf_protect
def admin_user_action(user_id):
    action = request.form.get("action")
    if action == "set_role":
        users_admin.update_user(user_id, role=request.form.get("role"), by=session["username"])
    elif action == "reset_mfa":
        users_admin.update_user(user_id, reset_mfa=True, by=session["username"])
    elif action == "deactivate":
        if user_id == session["user_id"]:
            abort(400, description="cannot deactivate your own account")
        users_admin.deactivate_user(user_id, by=session["username"])
    return redirect(url_for("web.admin_users"))
