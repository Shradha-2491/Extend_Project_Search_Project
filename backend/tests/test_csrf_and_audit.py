"""OWASP A01/CSRF on the Web interface, and OWASP A09 - Security Logging &
Monitoring Failures: the hash-chained audit log must detect tampering."""
import db


def test_web_post_without_csrf_token_is_rejected(client):
    resp = client.post("/register", data={
        "username": "nocsrf", "email": "nocsrf@example.test", "password": "abcdefghijk",
    })
    assert resp.status_code == 403


def test_web_post_with_valid_csrf_token_succeeds(client):
    get_resp = client.get("/register")
    assert get_resp.status_code == 200
    with client.session_transaction() as sess:
        token = sess["_csrf_token"]
    resp = client.post("/register", data={
        "csrf_token": token, "username": "withcsrf",
        "email": "withcsrf@example.test", "password": "abcdefghijk",
    })
    assert resp.status_code == 200
    assert b"Registered" in resp.data or b"Log in" in resp.data


def test_audit_log_tamper_is_detected(client):
    db.log_event("test_event", detail="original")
    ok, problems = db.verify_log_integrity()
    assert ok, problems

    # Simulate tampering: directly rewrite a row's details in the audit DB,
    # bypassing the application (the append-only triggers block UPDATE/DELETE
    # through normal SQL, so this uses a fresh unprotected connection to
    # prove the *hash chain*, not just the trigger, is what catches this).
    con = db.audit_connect()
    con.execute("DROP TRIGGER audit_log_no_update")
    con.execute("UPDATE audit_log SET details = '{\"detail\": \"tampered\"}' WHERE id = 1")
    con.commit()
    con.close()

    ok2, problems2 = db.verify_log_integrity()
    assert not ok2
    assert any("hash mismatch" in p or "chain link broken" in p for p in problems2)
