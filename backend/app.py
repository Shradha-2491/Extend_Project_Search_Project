"""Composition root: creates the Flask app, wires up shared extensions and
security headers, registers the legacy OWASP-injection teaching routes
(kept as-is -- they remain evidence for the Injection row of the OWASP
control table) plus the extended Web/API blueprints that implement product
management, RBAC, price protection, MFA, and user administration.
"""
import logging

from authlib.integrations.flask_client import OAuth
from flask import Flask, request, session, redirect, url_for, abort

import config
import db
import security
import templates
from extensions import limiter

app = Flask(__name__)
app.secret_key = config.LAB_SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=config.LAB_HTTPS,
    PERMANENT_SESSION_LIFETIME=__import__("datetime").timedelta(minutes=30),
    MAX_CONTENT_LENGTH=1024 * 1024,
    TEMPLATES_AUTO_RELOAD=False,
)

limiter.init_app(app)
app.jinja_env.globals["csrf_token"] = security.generate_csrf_token


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "script-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    if config.LAB_HTTPS:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers.pop("Server", None)
    return response


# ---------------------------------------------------------------------------
# Google OAuth client (web authorization-code flow). The mobile app uses a
# separate, secret-less native client id (config.GOOGLE_CLIENT_ID_MOBILE)
# verified independently in security.verify_google_id_token_mobile.
# ---------------------------------------------------------------------------

oauth = OAuth(app)
google_oauth = None
if config.GOOGLE_CLIENT_ID and config.GOOGLE_CLIENT_SECRET:
    google_oauth = oauth.register(
        name="google",
        client_id=config.GOOGLE_CLIENT_ID,
        client_secret=config.GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
else:
    logging.warning("GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET not set -- Google Sign-In is disabled.")


@app.route("/login/google")
@limiter.limit("10 per minute")
def google_login():
    if not google_oauth:
        abort(503, description="Google Sign-In is not configured on this server.")
    redirect_uri = url_for("web.google_callback_extended", _external=True)
    return google_oauth.authorize_redirect(redirect_uri)


# ---------------------------------------------------------------------------
# Register the extended Web + API blueprints
# ---------------------------------------------------------------------------

import web  # noqa: E402  (after `app`/`oauth` exist, web.py imports app.google_oauth lazily)
import api_auth  # noqa: E402
import api_products  # noqa: E402
import api_admin  # noqa: E402

app.register_blueprint(web.bp)
app.register_blueprint(api_auth.bp)
app.register_blueprint(api_products.bp)
app.register_blueprint(api_admin.bp)


@app.route("/")
def index():
    return templates.render_page(
        templates.INDEX_BODY,
        session_username=session.get("username"),
        session_role=session.get("role"),
        username=session.get("username"),
        role=session.get("role"),
        auth_provider=session.get("auth_provider", "local"),
        google_enabled=bool(google_oauth),
    )


@app.route("/logout")
def logout():
    db.log_event("logout", username=session.get("username"))
    session.clear()
    return templates.render_page(
        "<div class=\"ok\">Logged out.</div>", session_username=None, session_role=None
    )


@app.route("/reset-db", methods=["GET", "POST"])
@security.role_required("admin")
def reset_db():
    if request.method == "GET":
        return templates.render_page(templates.RESET_DB_CONFIRM_BODY,
                                      session_username=session.get("username"),
                                      session_role=session.get("role"))
    return _reset_db_confirmed()


@security.csrf_protect
def _reset_db_confirmed():
    db.init_db()
    db.log_event("db_reset", by=session.get("username"))
    return templates.render_page(
        "<div class=\"ok\"><strong>Database reset.</strong></div>",
        session_username=session.get("username"), session_role=session.get("role"),
    )


@app.route("/audit-log")
@security.role_required("admin")
def audit_log():
    ok, problems = db.verify_log_integrity()
    return templates.render_page(
        templates.AUDIT_LOG_BODY, session_username=session.get("username"),
        session_role=session.get("role"), entries=db.read_audit_log(),
        integrity_ok=ok, problems=problems,
    )


@app.errorhandler(403)
def forbidden_handler(e):
    return templates.render_page(
        templates.DENIED_BODY, session_username=session.get("username"),
        session_role=session.get("role"), logged_in=bool(session.get("username")),
    ), 403


@app.errorhandler(401)
def unauthorized_handler(e):
    if request.path.startswith("/api/"):
        return {"error": "unauthorized"}, 401
    return redirect(url_for("web.login2"))


@app.errorhandler(429)
def ratelimit_handler(e):
    from flask_limiter.util import get_remote_address
    db.log_event("rate_limited", path=request.path, ip=get_remote_address(),
                  username=session.get("username"), limit=str(e.description))
    if request.path.startswith("/api/"):
        return {"error": "rate_limited"}, 429
    return templates.render_page(
        "<h1>Too Many Requests</h1><div class=\"err\">You've made too many requests "
        "in a short time. Please wait and try again.</div>",
        session_username=session.get("username"), session_role=session.get("role"),
    ), 429


if __name__ == "__main__":
    db.init_db()
    db.init_audit_db()
    db.init_audit_flatfile()
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)
