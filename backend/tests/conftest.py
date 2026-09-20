import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("LAB_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("LAB_ENC_KEY", "kX2v1u1u9m1u5s6y7z8A9B0C1D2E3F4G5H6I7J8K9L0=")
    monkeypatch.setenv("LAB_HTTPS", "0")

    import config
    config.DB = tmp_path / "lab.db"
    config.AUDIT_DB_PATH = tmp_path / "audit.db"
    config.AUDIT_FLATFILE_PATH = tmp_path / "audit.log"
    config.MAIL_OUTBOX_DIR = tmp_path / "mail_outbox"

    import app as appmod
    from extensions import limiter as _limiter
    # Flask-Limiter reads RATELIMIT_ENABLED only once, at init_app() time (the
    # first `import app` in this process), so a later app.config change is
    # not enough -- flip the extension's own flag directly. Rate limiting
    # itself is proven against a live server in docs/test-evidence/ instead;
    # disabling it here just stops shared in-memory limiter state from
    # tripping unrelated tests that each log in several times per run.
    _limiter.enabled = False
    appmod.app.config.update(TESTING=True)
    import db
    db.init_db()
    db.init_audit_db()

    with appmod.app.test_client() as c:
        yield c


def login_and_verify_mfa(client, username, password):
    """Helper: password login -> enroll (if needed) -> verify -> full tokens."""
    import pyotp

    resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    data = resp.get_json()
    pending = data["pending_token"]

    if not data["mfa_enrolled"]:
        enroll = client.post(
            "/api/v1/auth/mfa/enroll", headers={"Authorization": f"Bearer {pending}"}
        ).get_json()
        secret = enroll["secret"]
    else:
        secret = None  # caller must know the secret for already-enrolled seed users in this test run

    code = pyotp.TOTP(secret).now()
    verify = client.post(
        "/api/v1/auth/mfa/verify", headers={"Authorization": f"Bearer {pending}"}, json={"code": code}
    ).get_json()
    return verify["access_token"]
