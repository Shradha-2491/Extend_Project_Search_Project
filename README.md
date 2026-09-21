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

## 1. Run the backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in LAB_SECRET_KEY / LAB_ENC_KEY (commands are in the file);
                        # Google Sign-In fields are optional
python3 app.py          # http://127.0.0.1:5001
```

First run auto-creates `lab.db` (seed users below) and `audit.db`/`audit.log`
(tamper-evident audit trail).

| Username | Password | Seed role |
|---|---|---|
| scott | tiger | customer |
| lalit | mohan | vendor |
| admin | admin-demo-password | admin |

All three currently have MFA **not yet enrolled** — the first login for each
will redirect to MFA setup (Web) or return `mfa_enrolled: false` from
`POST /api/v1/auth/login` (API/Mobile), per the assignment's mandatory-MFA
requirement.

## 2. Run the tests and security evidence

```bash
cd backend && source .venv/bin/activate
python3 -m pytest tests/ -v                 # 17 tests: RBAC, price protection, MFA, CSRF, audit-tamper


python3 ../docs/test-evidence/concurrency_price_race.py
python3 ../docs/test-evidence/resilience_induced_delay.py

bandit -r . -x ./.venv,./tests            # docs/scans/bandit_report.txt has the last run
pip-audit -r requirements.txt             # docs/scans/pip_audit_after_fix.txt has the last run
```

## 3. Open/build the mobile app

```bash
cd mobile/Product_Search_Project   # open this folder in Android Studio
```

The app was written and reviewed in an environment with no JDK/Android SDK,
so it could not be compiled here — Android Studio will resolve/verify the
Gradle setup on first sync. Debug builds talk to `10.0.2.2:5001` (emulator
loopback to your locally running backend) over plain HTTP by design (see
`network_security_config.xml` for the debug variant); release builds require
HTTPS + certificate pinning and have no such exception. Full build/sign/
inspect/MITM steps: `docs/mobile-security-checklist.md`.

## 4. Deliverables map

| Deliverable | Location |
|---|---|
| Source code | `backend/`, `mobile/` |
| Threat model | `docs/threat-model.md` |
| OWASP Risk → Control → Implementation → Component → Test Evidence table | `docs/owasp-control-table.md` |
| SBOM | `docs/sbom/backend-sbom.json` (tool-generated), `docs/sbom/mobile-sbom.json` (hand-authored, regeneration command included) |
| Scan reports + explanations | `docs/scans/README.md` (read this one), `docs/scans/bandit_report.txt`, `docs/scans/pip_audit_after_fix.txt` |
| Test evidence (incl. concurrency/resilience) | `docs/test-evidence/` |

## 5. Assignment objective checklist

| Objective | Where it's satisfied |
|---|---|
| Add/update/remove/search/view products | `backend/products.py` + `api_products.py` (`POST/PATCH/DELETE/GET /api/v1/products`) and `web.py` (`/products/*`) |
| Restrict product removal to authorized users | `security.role_required("vendor","admin")` / `api_role_required`, ownership re-checked in `products.soft_delete` |
| Define roles and permissions | `customer` / `vendor` / `admin` — see `docs/threat-model.md` §3 and the RBAC rows of `docs/owasp-control-table.md` |
| Role-scoped search (different fields/results per role) | `products.search()` / `visible_fields()` — one function for Web+API+Mobile; `tests/test_rbac.py` |
| Restrict price/total changes to authorized roles | `api_products.py::patch_price`, `web.py::product_price` — vendor-own or admin only |
| Protect against race conditions on price-sensitive ops | `products.update_price()` (version + Idempotency-Key in one transaction); `docs/test-evidence/concurrency_price_race.py` |
| Registration, login, logout, password recovery | `auth_service.py`, `web.py` (`/register`, `/login2`, `/logout`, `/password-reset/*`), `api_auth.py` |
| Instructor-approved MFA implemented and enforced | TOTP (`mfa.py`), mandatory for every account before a full session/token is issued (`auth_service`, `web.py`, `api_auth.py`) |
| Restrict user add/remove/update to admin | `users_admin.py` + `security.role_required("admin")`/`api_role_required("admin")`; `web.py::admin_users`, `api_admin.py` |
| Web, Mobile, API interfaces with consistent controls | Web (`web.py`/`app.py`), API (`api_*.py`), Mobile (`mobile/Product_Search_Project`) — all three call the same `security.py`/`products.py`/`auth_service.py`/`users_admin.py` functions |
| Google Sign-In implemented properly on Web and Mobile, `email_verified` actually checked | `security.validate_google_userinfo` (fixed to fail-closed — see `docs/threat-model.md` §7), `security.verify_google_id_token_mobile` (independent id_token verification for Mobile); `tests/test_mfa_and_google.py` |
| Mobile: inspect release APK for secrets/insecure storage/debug flags | `docs/mobile-security-checklist.md` §1–2 (needs Android Studio, not available in the environment that authored this project) |
| Mobile: demonstrate TLS enforcement / cert handling on a hostile network | `docs/mobile-security-checklist.md` §4 (needs a device + mitmproxy/Burp) |
| Threat model | `docs/threat-model.md` |
| OWASP risk mapping table | `docs/owasp-control-table.md` |
| SBOM | `docs/sbom/` |
| Scan reports with explanations | `docs/scans/README.md` |
| Test evidence incl. concurrency/resilience | `docs/test-evidence/` |
| Controls reusable/centralized, mapped to all applicable risks | `security.py`, `auth_service.py`, `products.py`, `users_admin.py` are each imported by every interface that needs them; `docs/owasp-control-table.md` marks each with **(shared)** and lists every risk it addresses |

## 6. What was reused vs. added

The original lab's audit-log hash chain, CSRF protection, rate limiting,
security headers, and parameterized-query pattern were kept and extended
(not rewritten) — they already satisfied several of the assignment's
"reusable, centralized" requirements. The original vulnerable/secure
injection routes (`/login`, `/search` vs. `/login-secure`, `/search-secure`)
are kept unchanged as the Injection row's before/after evidence in the
OWASP table, and are functionally isolated from the new RBAC/session system
(they never grant a real session).
