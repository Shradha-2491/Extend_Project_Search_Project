"""Serves the same Flask app over real HTTPS with a self-signed certificate,
as a synthetic stand-in for "your real classroom host" -- the assignment's
mobile objective needs the release build to talk to something over TLS with
certificate pinning, and per Rule 3 (synthetic test data only), this is a
locally-generated, throwaway CA rather than any real production endpoint.

Run this ALONGSIDE `python3 app.py` (which keeps serving plain HTTP on
:5001 for Web/API/debug-mobile testing) -- this listens on :5443. It does
NOT call db.init_db()/init_audit_db() itself: both processes share the same
lab.db/audit.db files, and only one of them should own schema
creation/reseeding (see app.py's own startup block).

    cd backend
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \\
      -keyout certs/server.key -out certs/server.crt \\
      -subj "/CN=10.0.2.2/O=Product Search Lab/OU=Synthetic Test CA" \\
      -addext "subjectAltName=IP:10.0.2.2,IP:127.0.0.1"
    python3 run_https.py   # https://10.0.2.2:5443/ from the emulator
"""
from pathlib import Path

from app import app
from config import BASE_DIR

CERT = BASE_DIR / "certs" / "server.crt"
KEY = BASE_DIR / "certs" / "server.key"

if __name__ == "__main__":
    if not CERT.exists() or not KEY.exists():
        raise SystemExit(
            f"Missing {CERT} / {KEY} -- generate them first (see this file's docstring)."
        )
    app.run(host="0.0.0.0", port=5443, debug=False, threaded=True, ssl_context=(str(CERT), str(KEY)))
