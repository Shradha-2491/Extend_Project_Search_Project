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


# ---------------------------------------------------------------------------
# Legacy OWASP injection-lab routes (unchanged behaviour): a deliberately
# vulnerable login/search pair next to a parameterized-query secure pair.
# Kept as-is -- they are the Injection row's test evidence in
# docs/owasp-control-table.md and are not part of the extended app's RBAC.
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
@security.csrf_protect
def vulnerable_login():
    ctx = {
        "title": "Vulnerable Login",
        "description": "This route intentionally concatenates form input into SQL "
                        "(SQL injection still possible here). Output is now escaped, "
                        "so XSS in the username/password fields is fixed. This route "
                        "never grants a real session, precisely because its query "
                        "result can't be trusted.",
        "username": "", "attempted": False, "logged_in_user": None,
        "logged_in_role": None, "error": None, "sql_display": "",
    }
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ctx["username"] = username
        ctx["attempted"] = True
        sql = ("SELECT id, username, role FROM users "
               f"WHERE username = '{username}' AND password = '{password}'")
        ctx["sql_display"] = sql
        try:
            con = db.connect()
            row = con.execute(sql).fetchone()
            con.close()
            if row:
                ctx["logged_in_user"] = row["username"]
                ctx["logged_in_role"] = row["role"]
        except db.sqlite3.Error as e:
            ctx["error"] = str(e)
    return templates.render_page(templates.LOGIN_BODY, session_username=session.get("username"),
                                  session_role=session.get("role"), **ctx)


@app.route("/login-secure", methods=["GET", "POST"])
@limiter.limit("5 per minute")
@security.csrf_protect
def secure_login():
    ctx = {
        "title": "Secure Login",
        "description": "Password is checked against a stored hash, never placed in SQL.",
        "username": "", "attempted": False, "logged_in_user": None,
        "logged_in_role": None, "error": None, "sql_display": "", "sql_params": "",
    }
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ctx["username"] = username
        ctx["attempted"] = True
        sql = "SELECT id, username, password, role, auth_provider FROM users WHERE username = ?"
        ctx["sql_display"] = sql
        ctx["sql_params"] = repr((username,))
        try:
            con = db.connect()
            row = con.execute(sql, (username,)).fetchone()
            con.close()
            ok = (row is not None and row["auth_provider"] == "local"
                  and row["password"] is not None
                  and security.verify_password(row["password"], password))
            if ok:
                ctx["logged_in_user"] = row["username"]
                ctx["logged_in_role"] = row["role"]
                db.log_event("login_success", username=row["username"], role=row["role"],
                              provider="local", route="legacy_secure_login")
            else:
                db.log_event("login_failed", username=username, provider="local",
                              route="legacy_secure_login")
        except db.sqlite3.Error as e:
            ctx["error"] = str(e)
    return templates.render_page(templates.LOGIN_BODY, session_username=session.get("username"),
                                  session_role=session.get("role"), **ctx)


@app.route("/search", methods=["GET", "POST"])
@limiter.limit("30 per minute")
@security.csrf_protect
def vulnerable_search():
    ctx = {
        "title": "Vulnerable Product Search",
        "description": "The search term is directly concatenated into SQL "
                        "(SQL injection still possible here). Output is now escaped, "
                        "so XSS via the search box is fixed.",
        "term": "", "rows": [], "error": None, "sql_display": "",
    }
    if request.method == "POST":
        term = request.form.get("term", "")
        ctx["term"] = term
        sql = f"SELECT id, name, category, price FROM products WHERE name LIKE '%{term}%'"
        ctx["sql_display"] = sql
        try:
            con = db.connect()
            ctx["rows"] = con.execute(sql).fetchall()
            con.close()
            db.log_event("search", route="vulnerable", username=session.get("username"),
                          term=term, result_count=len(ctx["rows"]))
        except db.sqlite3.Error as e:
            ctx["error"] = str(e)
            db.log_event("search_error", route="vulnerable", username=session.get("username"),
                          term=term, error=str(e))
    return templates.render_page(templates.SEARCH_BODY, session_username=session.get("username"),
                                  session_role=session.get("role"), **ctx)


@app.route("/search-secure", methods=["GET", "POST"])
@limiter.limit("30 per minute")
@security.csrf_protect
def secure_search():
    ctx = {
        "title": "Secure Product Search",
        "description": "The search term is bound as a parameter, never concatenated into SQL.",
        "term": "", "rows": [], "error": None, "sql_display": "", "sql_params": "",
    }
    if request.method == "POST":
        term = request.form.get("term", "")
        ctx["term"] = term
        sql = "SELECT id, name, category, price FROM products WHERE name LIKE ? ESCAPE '\\'"
        like_pattern = f"%{db.like_escape(term)}%"
        ctx["sql_display"] = sql
        ctx["sql_params"] = repr((like_pattern,))
        try:
            con = db.connect()
            ctx["rows"] = con.execute(sql, (like_pattern,)).fetchall()
            con.close()
            db.log_event("search", route="secure", username=session.get("username"),
                          term=term, result_count=len(ctx["rows"]))
        except db.sqlite3.Error as e:
            ctx["error"] = str(e)
            db.log_event("search_error", route="secure", username=session.get("username"),
                          term=term, error=str(e))
    return templates.render_page(templates.SEARCH_BODY, session_username=session.get("username"),
                                  session_role=session.get("role"), **ctx)


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
