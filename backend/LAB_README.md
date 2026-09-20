# OWASP Injection Lab — Setup

## Requirements
- Python 3.9+
- pip
- (Optional) Linux with ext2/3/4 and root/`CAP_LINUX_IMMUTABLE` — lets the
  app mark `audit.log` append-only via `chattr +a`. Without this, the app
  still runs fine; it just skips that extra OS-level protection.

## 1. Install
```bash
pip install flask flask-limiter authlib werkzeug python-dotenv
```

## 2. Create `.env`
Copy this into a file named `.env` next to `app.py`:

```properties
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

ADMIN_EMAILS=

LAB_SECRET_KEY=

LAB_HTTPS=0
```

- **GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET** — optional, enables "Sign in
  with Google". Get these from [Google Cloud Console](https://console.cloud.google.com/)
  → APIs & Services → Credentials → OAuth client ID (Web app). Add redirect URI:
  `http://127.0.0.1:5001/login/google/callback`. Leave blank to disable Google login.
- **ADMIN_EMAILS** — comma-separated emails that get `admin` role on first Google sign-in.
- **LAB_SECRET_KEY** — required for persistent sessions. Generate with:
  ```bash
  python3 -c "import secrets; print(secrets.token_hex(32))"
  ```
- **LAB_HTTPS** — `0` for local HTTP, `1` only if served over real HTTPS.

## 3. Run
```bash
python3 app.py
```
Opens on `http://127.0.0.1:5001`. On first run it auto-creates `lab.db`
(demo users/products) and `audit.db` / `audit.log` (audit trail).

## 4. Demo logins
| Username | Password | Role |
|---|---|---|
| scott | tiger | user |
| lalit | mohan | user |
| admin | admin-demo-password | admin |

**Never commit `.env` to git. Keep this app bound to 127.0.0.1 — it's intentionally vulnerable.**
