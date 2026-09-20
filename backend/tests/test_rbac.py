"""OWASP A01 - Broken Access Control: role-scoped search visibility and
RBAC enforcement on mutating endpoints, exercised through the JSON API."""
from tests.conftest import login_and_verify_mfa


def test_customer_search_hides_cost_and_inactive(client):
    token = login_and_verify_mfa(client, "scott", "tiger")
    resp = client.get("/api/v1/products", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    results = resp.get_json()["results"]
    assert len(results) == 4
    for row in results:
        assert set(row.keys()) == {"id", "name", "category", "price"}


def test_vendor_search_sees_only_own_inventory_with_cost_stock(client):
    token = login_and_verify_mfa(client, "lalit", "mohan")
    resp = client.get("/api/v1/products", headers={"Authorization": f"Bearer {token}"})
    results = resp.get_json()["results"]
    assert len(results) == 4  # lalit owns the seeded products
    for row in results:
        assert "cost" in row and "stock" in row
        assert "created_by" not in row  # admin-only audit field


def test_admin_search_sees_audit_fields(client):
    token = login_and_verify_mfa(client, "admin", "admin-demo-password")
    resp = client.get("/api/v1/products", headers={"Authorization": f"Bearer {token}"})
    results = resp.get_json()["results"]
    assert all("created_by" in row and "vendor_id" in row for row in results)


def test_customer_cannot_create_product(client):
    token = login_and_verify_mfa(client, "scott", "tiger")
    resp = client.post(
        "/api/v1/products", headers={"Authorization": f"Bearer {token}"},
        json={"name": "Hack", "category": "x", "price": 1, "stock": 1},
    )
    assert resp.status_code == 403


def test_vendor_cannot_edit_another_vendors_product(client):
    # Promote scott to vendor via a fresh admin session, then confirm scott
    # cannot touch lalit's products.
    admin_token = login_and_verify_mfa(client, "admin", "admin-demo-password")
    client.patch(
        "/api/v1/admin/users/1", headers={"Authorization": f"Bearer {admin_token}"},
        json={"role": "vendor"},
    )
    scott_token = login_and_verify_mfa(client, "scott", "tiger")
    resp = client.patch(
        "/api/v1/products/1", headers={"Authorization": f"Bearer {scott_token}"},
        json={"name": "Renamed"},
    )
    assert resp.status_code == 404  # not_found_or_forbidden -- no IDOR leak of existence either


def test_no_bearer_token_is_unauthorized(client):
    resp = client.get("/api/v1/products")
    assert resp.status_code == 401


def test_admin_only_user_admin_endpoints(client):
    token = login_and_verify_mfa(client, "scott", "tiger")
    resp = client.get("/api/v1/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
