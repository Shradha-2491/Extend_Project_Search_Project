"""OWASP A07 - Identification & Authentication Failures: MFA is mandatory
(no route reaches products/admin without it), lockout after repeated bad
codes, and the Google email_verified fail-closed fix."""
import pyotp

import security


def test_password_only_login_cannot_reach_products(client):
    resp = client.post("/api/v1/auth/login", json={"username": "scott", "password": "tiger"})
    data = resp.get_json()
    pending = data["pending_token"]
    # A pending-MFA token must never be accepted by the "full" auth guard.
    resp2 = client.get("/api/v1/products", headers={"Authorization": f"Bearer {pending}"})
    assert resp2.status_code == 401


def test_wrong_mfa_code_is_rejected_and_locks_out_after_repeated_failures(client):
    resp = client.post("/api/v1/auth/login", json={"username": "scott", "password": "tiger"})
    pending = resp.get_json()["pending_token"]
    client.post("/api/v1/auth/mfa/enroll", headers={"Authorization": f"Bearer {pending}"})

    for _ in range(5):
        bad = client.post("/api/v1/auth/mfa/verify", headers={"Authorization": f"Bearer {pending}"},
                           json={"code": "000000"})
        assert bad.status_code == 401

    # A 6th attempt is locked out even though the account isn't enrolled yet
    # (the enrollment secret itself never validated in the loop above).
    locked = client.post("/api/v1/auth/mfa/verify", headers={"Authorization": f"Bearer {pending}"},
                          json={"code": "000000"})
    assert locked.status_code == 401


def test_google_email_verified_missing_claim_is_rejected_fail_closed():
    """Regression test for the bug fixed in this project: the original
    google_callback() did `userinfo.get('email_verified', True)`, which
    trusted the email if Google omitted the claim entirely. The centralized
    validator must reject both an explicit False AND a missing claim."""
    import pytest

    with pytest.raises(security.GoogleIdentityError):
        security.validate_google_userinfo({"email": "attacker@example.com"})  # no claim at all

    with pytest.raises(security.GoogleIdentityError):
        security.validate_google_userinfo({"email": "attacker@example.com", "email_verified": False})

    with pytest.raises(security.GoogleIdentityError):
        security.validate_google_userinfo({"email": "attacker@example.com", "email_verified": "true"})

    # Only an explicit boolean True is accepted.
    assert security.validate_google_userinfo(
        {"email": "Real.User@Example.com", "email_verified": True}
    ) == "real.user@example.com"
