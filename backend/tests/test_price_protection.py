"""OWASP A04 - Insecure Design: optimistic concurrency + idempotency on the
price-sensitive endpoint. The real multi-thread proof lives in
docs/test-evidence/concurrency_price_race.py (needs a running server for
genuine parallel requests); these are the fast, deterministic single-process
checks of the same code path."""
from tests.conftest import login_and_verify_mfa


def _headers(token, idem="k1"):
    return {"Authorization": f"Bearer {token}", "Idempotency-Key": idem}


def test_price_update_requires_idempotency_key(client):
    token = login_and_verify_mfa(client, "lalit", "mohan")
    resp = client.patch(
        "/api/v1/products/1/price", headers={"Authorization": f"Bearer {token}"},
        json={"price": 20, "version": 1},
    )
    assert resp.status_code == 400


def test_stale_version_is_rejected_with_409(client):
    token = login_and_verify_mfa(client, "lalit", "mohan")
    ok = client.patch("/api/v1/products/1/price", headers=_headers(token, "a"),
                       json={"price": 20, "version": 1})
    assert ok.status_code == 200
    assert ok.get_json()["version"] == 2

    stale = client.patch("/api/v1/products/1/price", headers=_headers(token, "b"),
                          json={"price": 30, "version": 1})
    assert stale.status_code == 409
    assert stale.get_json()["error"] == "version_conflict"


def test_duplicate_idempotency_key_returns_cached_response_once(client):
    token = login_and_verify_mfa(client, "lalit", "mohan")
    first = client.patch("/api/v1/products/1/price", headers=_headers(token, "dup"),
                          json={"price": 42, "version": 1})
    second = client.patch("/api/v1/products/1/price", headers=_headers(token, "dup"),
                           json={"price": 42, "version": 1})
    assert first.status_code == 200 and second.status_code == 200
    assert first.get_json() == second.get_json()

    # only one price change actually took effect
    resp = client.get("/api/v1/products/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.get_json()["version"] == 2


def test_vendor_cannot_change_price_of_others_product(client):
    admin_token = login_and_verify_mfa(client, "admin", "admin-demo-password")
    client.patch("/api/v1/admin/users/1", headers={"Authorization": f"Bearer {admin_token}"},
                 json={"role": "vendor"})
    scott_token = login_and_verify_mfa(client, "scott", "tiger")
    resp = client.patch("/api/v1/products/1/price", headers=_headers(scott_token, "x"),
                         json={"price": 1, "version": 1})
    # 404, not 403 -- same anti-enumeration reasoning as the other
    # ownership-checked product endpoints (never confirm an id exists to a
    # non-owning vendor).
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "not_found_or_forbidden"
