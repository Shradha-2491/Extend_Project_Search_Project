# Extended Product & Product Search — Web, API, Mobile

Extension of the original OWASP-injection teaching lab into a full product
management system with RBAC, price protection, mandatory MFA, and matching
Web/API/Mobile interfaces, built for the "Extend the Existing Product and
Product Search Project" assignment.

```
backend/    Flask app (Web pages + JSON REST API), tests, security scans
mobile/     Android app (Kotlin/Compose) consuming the same REST API
docs/       Threat model, OWASP control table, SBOM, scan reports, test evidence
```

## 1. Requirements

- Python 3.9+ and pip
- For the mobile app: Android Studio (JDK + Android SDK bundled), or a
  standalone SDK + `./gradlew` from the command line
- (Optional) Linux with `chattr` available (ext2/3/4, `CAP_LINUX_IMMUTABLE`)
  — lets the backend mark `audit.log` append-only at the OS level. Without
  it, the app still runs fine; it just skips that extra hardening step and
  logs a warning.

## 2. Run the backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in the fields below
python3 app.py          # http://127.0.0.1:5001
```

**Never commit your real `.env`** — only `.env.example` (with blank/placeholder
values) belongs in git; `backend/.env` is already gitignored.

| `.env` field | Required? | What it's for |
|---|---|---|
| `LAB_SECRET_KEY` | Yes | Flask session signing. Generate: `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `LAB_ENC_KEY` | Yes | Encrypts MFA (TOTP) secrets at rest. Generate: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `LAB_HTTPS` | No (default `0`) | `1` marks session cookies `Secure` and adds HSTS — set this only if you're actually serving over HTTPS (see the synthetic HTTPS host in section 4). |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | No | Web Google Sign-In. See section 4 below. |
| `GOOGLE_CLIENT_ID_MOBILE` | No | Mobile Google Sign-In. See section 4 below. |
| `ADMIN_EMAILS` | No | Comma-separated emails that get the `admin` role on first Google sign-in. |

| Username | Password | Seed role |
|---|---|---|
| scott | tiger | customer |
| lalit | mohan | vendor |
| admin | admin-demo-password | admin |

All three start with MFA **not yet enrolled** — the first login for each
redirects to MFA setup (Web) or returns `mfa_enrolled: false` from
`POST /api/v1/auth/login` (API/Mobile), per the assignment's mandatory-MFA
requirement.

> ** The database resets on every backend restart.** `app.py` calls
> `db.init_db()` on startup, which unconditionally drops and recreates the
> `users`/`products` tables and reseeds only the three accounts above.
> Any account you register, any Google sign-in, any MFA enrollment, any
> price change — all gone the next time you run `python3 app.py`. This is
> intentional (a clean, reproducible starting state for grading/testing),
> not a bug. If you need data to survive a restart, don't restart the
> backend mid-test.

## 3. Run the tests and security evidence

```bash
cd backend && source .venv/bin/activate
pip install pytest bandit pip-audit         # dev-only tools, not in requirements.txt
python3 -m pytest tests/ -v                 # 17 tests: RBAC, price protection, MFA, CSRF, audit-tamper

python3 ../docs/test-evidence/concurrency_price_race.py
python3 ../docs/test-evidence/resilience_induced_delay.py

bandit -r . -x ./.venv,./tests            # docs/scans/bandit_report.txt has the last run
pip-audit -r requirements.txt             # docs/scans/pip_audit_after_fix.txt has the last run
```

All of the above are checked in with their actual output under
`docs/test-evidence/` and `docs/scans/` — you don't have to re-run them to
see the results, only to reproduce them. Read `docs/scans/README.md` for
what each finding means (several are intentional/false-positive and
explained there, not silently ignored).

## 4. Run the mobile app

```bash
cd mobile/Product_Search_Project   # open in Android Studio, or:
./gradlew installDebug             # build + install on a running emulator/device
```

Debug builds talk to `http://10.0.2.2:5001` — the Android emulator's
built-in alias for your host machine's `127.0.0.1` — over plain HTTP by
design (see `network_security_config.xml`'s debug variant, which only
allows cleartext to that one address). This only works with the actual
Android Studio emulator (AVD); a physical device would need your machine's
real LAN IP instead, with a matching entry in that same file.

**If the app can't reach the backend at all** (network/timeout errors even
though the backend is running): on very new Android system images (API 36+
preview builds), a new "Local Network Access" platform restriction can
silently block apps from connecting to private IPs like `10.0.2.2`, with no
way to grant it back yet. If you hit this, create the AVD with a stable,
non-preview system image (API 34 or 35, Google Play target) instead.

### Setting up Google Sign-In (optional, both Web and Mobile)

**Web** uses a standard server-side OAuth Authorization Code flow
(Authlib). In [Google Cloud Console → Credentials](https://console.cloud.google.com/apis/credentials):
1. Configure the OAuth consent screen if you haven't (External, add
   yourself as a test user is enough for local dev).
2. Create an OAuth client ID, type **Web application**.
3. Add authorized redirect URI: `http://127.0.0.1:5001/login/google/callback`.
4. Put the client ID and secret in `backend/.env` as `GOOGLE_CLIENT_ID` /
   `GOOGLE_CLIENT_SECRET`.

**Mobile** signs in via **Credential Manager** (Google's current native
Android sign-in API — see the doc comment in `GoogleAuthConfig.kt`), not a
browser redirect. Custom-scheme OAuth redirects are no longer supported by
Google on Android at all, so this is the only approach that works today.

1. Create **one more OAuth client ID of type "Web application"** (yes,
   Web — Credential Manager's `setServerClientId()` needs a Web client ID;
   there is no redirect URI to configure, and no Android-type client or
   SHA-1 fingerprint is needed for this flow). You can reuse the same Web
   client from the step above, or register a second one if you want mobile-
   and web-issued id_tokens to be mutually non-replayable across flows.
2. Put that client ID in **both** places (same value in both):
   - `backend/.env` → `GOOGLE_CLIENT_ID_MOBILE=<client id>`
   - `mobile/Product_Search_Project/app/build.gradle.kts` → the `debug` block's
     `buildConfigField("String", "GOOGLE_CLIENT_ID_MOBILE", "\"<client id>\"")`
3. Restart the backend (see the database-reset warning above) and reinstall
   the app.
4. The signed-in device/emulator needs a Google account added under
   Settings → Accounts for the Credential Manager account picker to have
   anything to show.

Leaving either field blank disables that platform's "Sign in with Google"
gracefully instead of crashing.

### Password reset, end to end

There's no real mail server here — see `backend/mail.py`'s docstring:
per the assignment rules, only synthetic test data is used, so "sending an
email" just writes a `.txt` file to `backend/mail_outbox/` for you to read.

- **Web**: `/password-reset/request` → the file in `mail_outbox/` now
  contains a real, clickable link with the token pre-filled
  (`http://.../password-reset/confirm?token=...`) — open it and set a new
  password.
- **Mobile**: the "Forgot password" screen has two sections — request a
  reset, then paste the token from the same `mail_outbox/` file into the
  "Already have a reset token?" section below it, along with a new password.

### Release build, APK inspection, and the MITM/pinning demo

No real classroom host was provided for this assignment, so — per Rule 3
(synthetic test data only) — the release build and its certificate pinning
point at a **locally-generated synthetic HTTPS host** instead of a real one:

```bash
cd backend
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=10.0.2.2/O=Product Search Lab/OU=Synthetic Test CA" \
  -addext "subjectAltName=IP:10.0.2.2,IP:127.0.0.1"
python3 run_https.py   # serves the SAME app on :5443 over HTTPS,
                        # alongside `python3 app.py` on :5001 for HTTP
```

The release build's `API_BASE_URL` (`https://10.0.2.2:5443/`) and
`network_security_config.xml`'s pinned domain/certificate are already
wired to this synthetic host — see `docs/scans/mobile/mitm_pinning_test.txt`
for the full walkthrough, including the actual negative test (a substituted
certificate gets rejected with `SSLHandshakeException`, proving the pinning
fails closed) run against this exact setup.

Building, signing, and inspecting the release APK for secrets/debuggable
flags, and verifying `TokenStore`'s encrypted local storage, are all
runnable with the Android SDK's own `build-tools` (`apksigner`, `aapt`,
`zipalign` — no extra tools needed for these three). Full step-by-step
commands: `docs/mobile-security-checklist.md`. Evidence from the last run:
`docs/scans/mobile/`.

## 5. Deliverables map

| Deliverable | Location |
|---|---|
| Source code | `backend/`, `mobile/` |
| Threat model | `docs/threat-model.md` |
| OWASP Risk → Control → Implementation → Component → Test Evidence table | `docs/owasp-control-table.md` |
| SBOM | `docs/sbom/backend-sbom.json` (32 components, `pip-audit --format=cyclonedx-json`), `docs/sbom/mobile-sbom.json` (282 components, CycloneDX Gradle plugin — regenerate with `./gradlew cyclonedxBom`) — both tool-generated against the actual current dependency graph, not hand-authored |
| Scan reports + explanations | `docs/scans/README.md` (read this one), `docs/scans/bandit_report.txt`, `docs/scans/pip_audit_after_fix.txt`, `docs/scans/mobile/` |
| Test evidence (incl. concurrency/resilience) | `docs/test-evidence/` |

## 6. Assignment objective checklist

| Objective | Where it's satisfied |
|---|---|
| Add/update/remove/search/view products | `backend/products.py` + `api_products.py` (`POST/PATCH/DELETE/GET /api/v1/products`) and `web.py` (`/products/*`) |
| Restrict product removal to authorized users | `security.role_required("vendor","admin")` / `api_role_required`, ownership re-checked in `products.soft_delete` |
| Define roles and permissions | `customer` / `vendor` / `admin` — see `docs/threat-model.md` §3 and the RBAC rows of `docs/owasp-control-table.md` |
| Role-scoped search (different fields/results per role) | `products.search()` / `visible_fields()` — one function for Web+API+Mobile; `tests/test_rbac.py` |
| Restrict price/total changes to authorized roles | `api_products.py::patch_price`, `web.py::product_price` — vendor-own or admin only |
| Protect against race conditions on price-sensitive ops | `products.update_price()` (version + Idempotency-Key in one transaction); `docs/test-evidence/concurrency_price_race.py` (verified: 10 concurrent stale writes → 1 winner + 9×409; 10 duplicate submits → exactly 1 applied) |
| Registration, login, logout, password recovery | `auth_service.py`, `web.py` (`/register`, `/login2`, `/logout`, `/password-reset/*`), `api_auth.py`, mobile confirm screen in `AuthScreens.kt` |
| Instructor-approved MFA implemented and enforced | TOTP (`mfa.py`), mandatory for every account before a full session/token is issued (`auth_service`, `web.py`, `api_auth.py`) |
| Restrict user add/remove/update to admin | `users_admin.py` + `security.role_required("admin")`/`api_role_required("admin")`; `web.py::admin_users`, `api_admin.py` |
| Web, Mobile, API interfaces with consistent controls | Web (`web.py`/`app.py`), API (`api_*.py`), Mobile (`mobile/Product_Search_Project`) — all three call the same `security.py`/`products.py`/`auth_service.py`/`users_admin.py` functions |
| Google Sign-In implemented properly on Web and Mobile, `email_verified` actually checked | `security.validate_google_userinfo` (fixed to fail-closed — see `docs/threat-model.md` §7), `security.verify_google_id_token_mobile` (independent id_token verification for Mobile, via Credential Manager — see section 4 above); `tests/test_mfa_and_google.py` |
| Mobile: inspect release APK for secrets/insecure storage/debug flags | **Done** — `docs/scans/mobile/apk_secret_scan.txt`, `apk_debuggable_check.txt`, `local_storage_check.txt`. Clean: no secrets, non-debuggable, `allowBackup=false`, R8 minification confirmed active, tokens stored encrypted (AES-256-SIV/GCM). |
| Mobile: demonstrate TLS enforcement / cert handling on a hostile network | **Done** — `docs/scans/mobile/mitm_pinning_test.txt`, against a synthetic local HTTPS host (see section 4). Substituted-certificate connection fails closed with `SSLHandshakeException`; legitimate certificate works; both confirmed against the real signed, R8-minified release build. |
| Threat model | `docs/threat-model.md` |
| OWASP risk mapping table | `docs/owasp-control-table.md` |
| SBOM | `docs/sbom/` — both real, tool-generated, complete dependency inventories (see section 5) |
| Scan reports with explanations | `docs/scans/README.md` |
| Test evidence incl. concurrency/resilience | `docs/test-evidence/` — pytest 17/17 passing, concurrency race PASS, induced-delay resilience PASS, rate-limit evidence included |
| Controls reusable/centralized, mapped to all applicable risks | `security.py`, `auth_service.py`, `products.py`, `users_admin.py` are each imported by every interface that needs them; `docs/owasp-control-table.md` marks each with **(shared)** and lists every risk it addresses |

## 7. What was reused vs. added

The original lab's audit-log hash chain, CSRF protection, rate limiting,
security headers, and parameterized-query pattern were kept and extended
(not rewritten) — they already satisfied several of the assignment's
"reusable, centralized" requirements. The original vulnerable/secure
injection routes (`/login`, `/search` vs. `/login-secure`, `/search-secure`)
are kept unchanged as the Injection row's before/after evidence in the
OWASP table, and are functionally isolated from the new RBAC/session system
(they never grant a real session).
