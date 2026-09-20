"""Jinja string templates shared by app.py (legacy injection-lab routes) and
web.py (extended product/account/admin pages). Deliberately no client-side
JavaScript anywhere -- the CSP in app.py sets `script-src 'none'`, so every
interaction here is a plain HTML form/link, consistent with the original lab."""
from flask import render_template_string

PAGE_HEAD = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Extended Product Search Lab</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 960px; margin: 40px auto; line-height: 1.5; }
    code, pre { background: #f4f4f4; padding: 3px 6px; border-radius: 4px; white-space: pre-wrap; word-break: break-word; }
    pre { padding: 12px; overflow-x: auto; }
    .warn { background: #fff3cd; padding: 12px; border-left: 5px solid #ffcc00; }
    .ok { background: #e8f5e9; padding: 12px; border-left: 5px solid #43a047; }
    .err { background: #fdecea; padding: 12px; border-left: 5px solid #e53935; }
    table { border-collapse: collapse; width: 100%; font-size: 0.9em; }
    th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left; vertical-align: top; }
    th { background: #f4f4f4; }
    a { margin-right: 16px; }
    nav { margin-bottom: 20px; }
    fieldset { margin-bottom: 16px; }
  </style>
</head>
<body>
"""

PAGE_FOOT = """
</body>
</html>
"""

NAV = """
<nav>
  <a href="/">Home</a>
  {% if session_username %}
    <a href="/products">Products</a>
    {% if session_role in ('vendor','admin') %}<a href="/products/new">Add product</a>{% endif %}
    {% if session_role == 'admin' %}<a href="/admin/users">User admin</a><a href="/audit-log">Audit log</a>{% endif %}
    <a href="/logout">Log out ({{ session_username }}/{{ session_role }})</a>
  {% else %}
    <a href="/register">Register</a>
    <a href="/login2">Log in</a>
    <a href="/login/google">Sign in with Google</a>
  {% endif %}
</nav>
"""


def render_page(content_template, **ctx):
    return render_template_string(PAGE_HEAD + NAV + content_template + PAGE_FOOT, **ctx)


DENIED_BODY = """
<h1>Access Denied</h1>
{% if logged_in %}
  <div class="err">You're logged in, but this account does not have permission to do that.</div>
{% else %}
  <div class="err">You must log in to do that.</div>
{% endif %}
"""

RESET_DB_CONFIRM_BODY = """
<h1>Reset Database</h1>
<div class="warn">This will drop and recreate the <code>users</code> and <code>products</code>
tables. CSRF-protected POST, not a plain link.</div>
<form method="post" action="/reset-db">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <button type="submit">Confirm reset</button>
</form>
"""

INDEX_BODY = """
<h1>Extended Product Search Lab</h1>
<div class="warn">
  <strong>IIT Hyderabad - Secure Software Engg:</strong> educational lab.
  Keep it bound to 127.0.0.1 or an isolated cyber range.
</div>
{% if username %}
  <p>Signed in as <strong>{{ username }}</strong> ({{ role }}, via {{ auth_provider }}).</p>
{% else %}
  <p>Not signed in.</p>
{% endif %}
<h2>Extended app (product mgmt, RBAC, MFA, price protection)</h2>
<ul>
  <li><a href="/register">Register</a></li>
  <li><a href="/login2">Log in (password, MFA-enforced)</a></li>
  {% if google_enabled %}<li><a href="/login/google">Sign in with Google</a></li>{% endif %}
  <li><a href="/password-reset/request">Forgot password</a></li>
  <li><a href="/products">Product search (role-scoped)</a></li>
</ul>
<h2>Original OWASP injection lab (kept for the Injection control's evidence)</h2>
<ul>
  <li><a href="/login">Vulnerable Login</a></li>
  <li><a href="/login-secure">Secure Login</a></li>
  <li><a href="/search">Vulnerable Search</a></li>
  <li><a href="/search-secure">Secure Search</a></li>
  <li><a href="/reset-db">Reset Database</a> (admin only)</li>
  <li><a href="/audit-log">Audit Log</a> (admin only)</li>
</ul>
"""

LOGIN_BODY = """
<h1>{{ title }}</h1>
<p>{{ description }}</p>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <p>Username: <input name="username" value="{{ username }}"></p>
  <p>Password: <input name="password" type="password"></p>
  <button type="submit">Login</button>
</form>
{% if error %}<div class="err"><strong>Error:</strong> {{ error }}</div>{% endif %}
{% if logged_in_user %}
  <div class="warn">logged in as {{ logged_in_user }} ({{ logged_in_role }}).</div>
{% elif attempted %}<p>Login failed.</p>{% endif %}
{% if sql_display %}
  <h3>SQL executed by the application</h3><pre>{{ sql_display }}</pre>
  {% if sql_params is defined %}
    <h3>Parameters bound separately (never concatenated into the SQL string)</h3>
    <pre>{{ sql_params }}</pre>
  {% endif %}
{% endif %}
"""

SEARCH_BODY = """
<h1>{{ title }}</h1>
<p>{{ description }}</p>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="term" placeholder="Search products" value="{{ term }}">
  <button type="submit">Search</button>
</form>
{% if error %}<div class="err"><strong>SQL error:</strong> {{ error }}</div>{% endif %}
<h3>Results</h3>
<ul>
  {% for r in rows %}
    <li>{{ r['name'] }} — {{ r['category'] }} — ${{ '%.2f'|format(r['price']) }}</li>
  {% else %}<li>No results.</li>{% endfor %}
</ul>
{% if sql_display %}
  <h3>SQL executed by the application</h3><pre>{{ sql_display }}</pre>
  {% if sql_params is defined %}
    <h3>Parameters bound separately (never concatenated into the SQL string)</h3>
    <pre>{{ sql_params }}</pre>
  {% endif %}
{% endif %}
"""

AUDIT_LOG_BODY = """
<h1>Audit Log</h1>
{% if integrity_ok %}
  <div class="ok"><strong>Integrity check passed.</strong> The hash chain is intact.</div>
{% else %}
  <div class="err"><strong>Integrity check FAILED.</strong>
    <ul>{% for p in problems %}<li>{{ p }}</li>{% endfor %}</ul>
  </div>
{% endif %}
<table>
  <tr><th>#</th><th>Time (UTC)</th><th>Event</th><th>Details</th><th>Hash</th></tr>
  {% for e in entries %}
    <tr>
      <td>{{ loop.index }}</td><td>{{ e.ts }}</td><td>{{ e.event }}</td>
      <td><pre>{{ e.details }}</pre></td><td><code>{{ e.hash[:12] }}...</code></td>
    </tr>
  {% else %}<tr><td colspan="5">No log entries yet.</td></tr>{% endfor %}
</table>
"""

# --- Extended app templates -------------------------------------------------

REGISTER_BODY = """
<h1>Register</h1>
<p>Creates a <code>customer</code> account. Vendor access must be granted by an admin afterward.</p>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <p>Username: <input name="username"></p>
  <p>Email: <input name="email" type="email"></p>
  <p>Password (min 10 chars): <input name="password" type="password"></p>
  <button type="submit">Register</button>
</form>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
{% if success %}<div class="ok">Registered. <a href="/login2">Log in</a> and you'll be asked to set up MFA.</div>{% endif %}
"""

LOGIN2_BODY = """
<h1>Log in</h1>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <p>Username: <input name="username"></p>
  <p>Password: <input name="password" type="password"></p>
  <button type="submit">Login</button>
</form>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<p><a href="/password-reset/request">Forgot password?</a></p>
"""

MFA_SETUP_BODY = """
<h1>Set up MFA (required)</h1>
<p>Scan this QR with an authenticator app (Google Authenticator, Authy, etc.),
or enter the secret manually, then submit the current 6-digit code.</p>
<img src="{{ qr_data_uri }}" alt="MFA QR code">
<p>Manual secret: <code>{{ secret }}</code></p>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <p>Code: <input name="code" autocomplete="one-time-code"></p>
  <button type="submit">Activate MFA</button>
</form>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
"""

MFA_VERIFY_BODY = """
<h1>Two-factor verification</h1>
<p>Enter the 6-digit code from your authenticator app.</p>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <p>Code: <input name="code" autocomplete="one-time-code"></p>
  <button type="submit">Verify</button>
</form>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
"""

# nosec B105 -- Bandit's variable-name heuristic flags PASSWORD_RESET_*_BODY
# below as a "hardcoded password" because of the name; it's HTML template
# text, not a credential.
PASSWORD_RESET_REQUEST_BODY = """
<h1>Forgot password</h1>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <p>Username or email: <input name="identifier"></p>
  <button type="submit">Send reset instructions</button>
</form>
{% if sent %}
  <div class="ok">If an account exists, reset instructions were written to
  <code>backend/mail_outbox/</code> (this lab has no real mail relay).</div>
{% endif %}
"""

# nosec B105 -- same false positive as PASSWORD_RESET_REQUEST_BODY above.
PASSWORD_RESET_CONFIRM_BODY = """
<h1>Reset password</h1>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <p>Reset token: <input name="token" value="{{ token }}"></p>
  <p>New password (min 10 chars): <input name="new_password" type="password"></p>
  <button type="submit">Reset</button>
</form>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
{% if success %}<div class="ok">Password updated. <a href="/login2">Log in</a>.</div>{% endif %}
"""

PRODUCTS_BODY = """
<h1>Products ({{ session_role }} view)</h1>
<p>{{ scope_note }}</p>
<form method="get">
  <input name="q" placeholder="Search" value="{{ term }}">
  <button type="submit">Search</button>
</form>
<table>
  <tr>{% for f in fields %}<th>{{ f }}</th>{% endfor %}<th>Actions</th></tr>
  {% for r in rows %}
    <tr>
      {% for f in fields %}<td>{{ r[f] }}</td>{% endfor %}
      <td>
        {% if session_role in ('vendor','admin') %}
          <a href="/products/{{ r['id'] }}/edit">Edit</a>
          <a href="/products/{{ r['id'] }}/price">Change price</a>
        {% endif %}
      </td>
    </tr>
  {% else %}<tr><td colspan="{{ fields|length + 1 }}">No results.</td></tr>{% endfor %}
</table>
"""

PRODUCT_NEW_BODY = """
<h1>Add product</h1>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <p>Name: <input name="name"></p>
  <p>Category: <input name="category"></p>
  <p>Price: <input name="price"></p>
  <p>Cost: <input name="cost"></p>
  <p>Stock: <input name="stock"></p>
  <button type="submit">Create</button>
</form>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
"""

PRODUCT_EDIT_BODY = """
<h1>Edit product #{{ product.id }}</h1>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <p>Name: <input name="name" value="{{ product.name }}"></p>
  <p>Category: <input name="category" value="{{ product.category }}"></p>
  <p>Stock: <input name="stock" value="{{ product.stock }}"></p>
  <p>Active: <select name="active"><option value="1" {% if product.active %}selected{% endif %}>Yes</option>
    <option value="0" {% if not product.active %}selected{% endif %}>No</option></select></p>
  <button type="submit">Save</button>
</form>
<form method="post" action="/products/{{ product.id }}/delete">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <button type="submit">Remove (deactivate)</button>
</form>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
{% if success %}<div class="ok">Saved.</div>{% endif %}
"""

PRODUCT_PRICE_BODY = """
<h1>Change price for product #{{ product.id }} ({{ product.name }})</h1>
<p>Current price: ${{ '%.2f'|format(product.price) }} (version {{ product.version }})</p>
<p>Submitting this form sends the version you last saw plus a fresh, unique
Idempotency-Key so a double-click or a browser retry can never apply the
change twice, and a concurrent edit by someone else is rejected as a 409
conflict instead of silently overwritten.</p>
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input type="hidden" name="version" value="{{ product.version }}">
  <input type="hidden" name="idempotency_key" value="{{ idempotency_key }}">
  <p>New price: <input name="price"></p>
  <button type="submit">Update price</button>
</form>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
{% if success %}<div class="ok">Price updated to ${{ '%.2f'|format(product.price) }} (version {{ product.version }}).</div>{% endif %}
"""

ADMIN_USERS_BODY = """
<h1>User administration</h1>
<table>
  <tr><th>id</th><th>username</th><th>email</th><th>role</th><th>provider</th>
      <th>active</th><th>mfa</th><th>actions</th></tr>
  {% for u in users %}
    <tr>
      <td>{{ u.id }}</td><td>{{ u.username }}</td><td>{{ u.email }}</td><td>{{ u.role }}</td>
      <td>{{ u.auth_provider }}</td><td>{{ u.active }}</td><td>{{ u.mfa_enabled }}</td>
      <td>
        <form method="post" action="/admin/users/{{ u.id }}" style="display:inline">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <select name="role">
            {% for r in ('customer','vendor','admin') %}
              <option value="{{ r }}" {% if r == u.role %}selected{% endif %}>{{ r }}</option>
            {% endfor %}
          </select>
          <button type="submit" name="action" value="set_role">Set role</button>
          <button type="submit" name="action" value="reset_mfa">Reset MFA</button>
          <button type="submit" name="action" value="deactivate">Deactivate</button>
        </form>
      </td>
    </tr>
  {% endfor %}
</table>
<h2>Add user</h2>
<form method="post" action="/admin/users">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <p>Username: <input name="username"></p>
  <p>Email: <input name="email"></p>
  <p>Password: <input name="password" type="password"></p>
  <p>Role: <select name="role"><option>customer</option><option>vendor</option><option>admin</option></select></p>
  <button type="submit">Create</button>
</form>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
"""
