"""Negative-path RBAC evidence: for every role, actively try operations that
role should NOT be able to do (not just confirm the ones it can), across
product management, price protection, and user administration -- exercising
security.api_role_required / products._owns_or_admin the same way an
attacker with a legitimately-issued token for a lower role would.

Run against a freshly-started backend (`python3 app.py`):
    python3 docs/test-evidence/negative_authz_matrix.py
"""
import sys
import uuid

import pyotp
import requests

BASE = "http://127.0.0.1:5001/api/v1"
PASS, FAIL = "PASS", "FAIL"
results = []


def record(desc, ok):
    results.append((PASS if ok else FAIL, desc))
    print(f"[{PASS if ok else FAIL}] {desc}")


def login_and_get_token(username, password):
    r = requests.post(f"{BASE}/auth/login", json={"username": username, "password": password})
    r.raise_for_status()
    body = r.json()
    pending = body["pending_token"]
    if not body["mfa_enrolled"]:
        enroll = requests.post(f"{BASE}/auth/mfa/enroll",
                                headers={"Authorization": f"Bearer {pending}"})
        enroll.raise_for_status()
        secret = enroll.json()["secret"]
    else:
        raise RuntimeError(f"{username} already has MFA enrolled; this script needs a fresh DB "
                            "(restart the backend, which reseeds it) or hardcode its secret.")
    code = pyotp.TOTP(secret).now()
    verify = requests.post(f"{BASE}/auth/mfa/verify", headers={"Authorization": f"Bearer {pending}"},
                            json={"code": code})
    verify.raise_for_status()
    return verify.json()["access_token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def main():
    print("=== Setting up: logging in seed accounts, enrolling MFA fresh ===")
    customer_token = login_and_get_token("scott", "tiger")
    vendor_a_token = login_and_get_token("lalit", "mohan")
    admin_token = login_and_get_token("admin", "admin-demo-password")

    print("\n=== Admin creates a second vendor + their own product, for cross-vendor tests ===")
    vendor_b_username = f"vendorb_{uuid.uuid4().hex[:8]}"
    vendor_b_password = "SynthVendorB!2345"
    r = requests.post(f"{BASE}/admin/users", headers=auth(admin_token), json={
        "username": vendor_b_username, "email": f"{vendor_b_username}@example.test",
        "password": vendor_b_password, "role": "vendor",
    })
    r.raise_for_status()
    vendor_b_token = login_and_get_token(vendor_b_username, vendor_b_password)

    r = requests.post(f"{BASE}/products", headers=auth(vendor_b_token), json={
        "name": "Vendor B synthetic widget", "category": "Test", "price": 9.99, "stock": 5,
    })
    r.raise_for_status()
    vendor_b_product_id = r.json()["id"]

    r = requests.get(f"{BASE}/products", headers=auth(vendor_a_token))
    r.raise_for_status()
    vendor_a_product_id = next(p["id"] for p in r.json()["results"])

    print("\n=== CUSTOMER trying vendor/admin-only operations (all must be denied) ===")
    r = requests.post(f"{BASE}/products", headers=auth(customer_token),
                       json={"name": "x", "category": "y", "price": 1})
    record("customer cannot create a product (expect 403)", r.status_code == 403)

    r = requests.patch(f"{BASE}/products/{vendor_a_product_id}/price",
                        headers={**auth(customer_token), "Idempotency-Key": str(uuid.uuid4())},
                        json={"price": 1, "version": 1})
    record("customer cannot change a price (expect 403)", r.status_code == 403)

    r = requests.patch(f"{BASE}/products/{vendor_a_product_id}", headers=auth(customer_token),
                        json={"stock": 999})
    record("customer cannot patch product fields (expect 403)", r.status_code == 403)

    r = requests.delete(f"{BASE}/products/{vendor_a_product_id}", headers=auth(customer_token))
    record("customer cannot delete a product (expect 403)", r.status_code == 403)

    r = requests.get(f"{BASE}/admin/users", headers=auth(customer_token))
    record("customer cannot list users (expect 403)", r.status_code == 403)

    r = requests.post(f"{BASE}/admin/users", headers=auth(customer_token),
                       json={"username": "x", "email": "x@example.test", "password": "whatever123", "role": "admin"})
    record("customer cannot create a user (expect 403)", r.status_code == 403)

    r = requests.get(f"{BASE}/admin/audit-log", headers=auth(customer_token))
    record("customer cannot read the audit log (expect 403)", r.status_code == 403)

    print("\n=== CUSTOMER information-disclosure check (role-scoped field visibility) ===")
    r = requests.get(f"{BASE}/products", headers=auth(customer_token))
    r.raise_for_status()
    leaked = [p for p in r.json()["results"] if "cost" in p or "stock" in p]
    record("customer's search response never includes cost/stock fields", len(leaked) == 0)
    inactive_visible = [p for p in r.json()["results"] if p.get("active") is False]
    record("customer never sees inactive/deactivated listings", len(inactive_visible) == 0)

    print("\n=== VENDOR trying admin-only operations (all must be denied) ===")
    r = requests.get(f"{BASE}/admin/users", headers=auth(vendor_a_token))
    record("vendor cannot list users (expect 403)", r.status_code == 403)

    r = requests.patch(f"{BASE}/admin/users/1", headers=auth(vendor_a_token), json={"role": "admin"})
    record("vendor cannot change a user's role (expect 403)", r.status_code == 403)

    r = requests.delete(f"{BASE}/admin/users/1", headers=auth(vendor_a_token))
    record("vendor cannot deactivate a user (expect 403)", r.status_code == 403)

    r = requests.get(f"{BASE}/admin/audit-log", headers=auth(vendor_a_token))
    record("vendor cannot read the audit log (expect 403)", r.status_code == 403)

    print("\n=== VENDOR A trying to touch VENDOR B's product (anti-IDOR, all must be denied) ===")
    r = requests.patch(f"{BASE}/products/{vendor_b_product_id}/price",
                        headers={**auth(vendor_a_token), "Idempotency-Key": str(uuid.uuid4())},
                        json={"price": 0.01, "version": 1})
    record("vendor A cannot change vendor B's price (expect 404, not 403 -- hides existence)",
           r.status_code == 404)

    r = requests.patch(f"{BASE}/products/{vendor_b_product_id}", headers=auth(vendor_a_token),
                        json={"stock": 999999})
    record("vendor A cannot patch vendor B's product fields (expect 404)", r.status_code == 404)

    r = requests.delete(f"{BASE}/products/{vendor_b_product_id}", headers=auth(vendor_a_token))
    record("vendor A cannot delete vendor B's product (expect 404)", r.status_code == 404)

    print("\n=== VENDOR's own search results only show their own inventory ===")
    r = requests.get(f"{BASE}/products", headers=auth(vendor_a_token))
    r.raise_for_status()
    foreign = [p for p in r.json()["results"] if p["id"] == vendor_b_product_id]
    record("vendor A's search never returns vendor B's product", len(foreign) == 0)

    print("\n=== No token / bad token on protected endpoints ===")
    r = requests.get(f"{BASE}/products")
    record("no bearer token -> 401 on a protected endpoint", r.status_code == 401)

    r = requests.get(f"{BASE}/products", headers={"Authorization": "Bearer not-a-real-jwt"})
    record("garbage bearer token -> 401", r.status_code == 401)

    r = requests.get(f"{BASE}/admin/users", headers=auth(customer_token))
    r2 = requests.get(f"{BASE}/admin/users")
    record("no token on admin endpoint -> 401, not the 403 a valid-but-wrong-role token gets",
           r2.status_code == 401 and r.status_code == 403)

    print("\n=== Privilege escalation at registration ===")
    reg_username = f"escalate_{uuid.uuid4().hex[:8]}"
    r = requests.post(f"{BASE}/auth/register", json={
        "username": reg_username, "email": f"{reg_username}@example.test",
        "password": "SynthPassword!234", "role": "admin",
    })
    record("registration accepted (expect 2xx)", r.status_code < 300)
    admin_check = requests.get(f"{BASE}/admin/users", headers=auth(admin_token))
    admin_check.raise_for_status()
    created = next(u for u in admin_check.json()["results"] if u["username"] == reg_username)
    record(f"self-registered user got role={created['role']!r}, NOT the requested 'admin'",
           created["role"] == "customer")

    print("\n=== Positive control: ADMIN can do all of the above (restrictions aren't overly broad) ===")
    r = requests.get(f"{BASE}/admin/users", headers=auth(admin_token))
    record("admin CAN list users", r.status_code == 200)
    r = requests.get(f"{BASE}/admin/audit-log", headers=auth(admin_token))
    record("admin CAN read the audit log", r.status_code == 200)
    r = requests.patch(f"{BASE}/products/{vendor_b_product_id}", headers=auth(admin_token),
                        json={"stock": 42})
    record("admin CAN patch any vendor's product", r.status_code == 200)

    print("\n" + "=" * 60)
    passed = sum(1 for s, _ in results if s == PASS)
    print(f"{passed}/{len(results)} checks passed")
    if passed != len(results):
        print("FAILURES:")
        for s, d in results:
            if s == FAIL:
                print(f"  - {d}")
        sys.exit(1)


if __name__ == "__main__":
    main()
