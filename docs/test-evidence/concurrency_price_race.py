"""Reproducible concurrency evidence for the price-protection control.

Run with the backend already running (python3 app.py, threaded=True) and a
vendor JWT access token in VENDOR_TOKEN, e.g.:

    export VENDOR_TOKEN=<paste access_token from /api/v1/auth/mfa/verify>
    python3 concurrency_price_race.py

What this proves
-----------------
Test 1 fires 10 simultaneous PATCH requests at the same product, all quoting
the SAME (now-stale-to-9-of-them) `version`. Because products.update_price()
performs the version check and the UPDATE inside one SQLite
`BEGIN IMMEDIATE` transaction, exactly one request can hold the write lock
and succeed (200); the other 9 observe rowcount=0 and get a clean 409
version_conflict instead of silently losing or double-applying an update.

Test 2 fires 10 simultaneous PATCH requests carrying the SAME
`Idempotency-Key`. The first to acquire the write lock inserts both the
price change and the idempotency-cache row atomically; every other
concurrent holder of that key -- even ones that started before the first
one committed -- sees the cached row once they get the lock and returns the
identical cached response. The product's `version` therefore advances by
exactly 1, not 10, proving a double-click/retry storm cannot double-charge
or double-decrement stock.
"""
import concurrent.futures
import os
import sys

import requests

BASE = os.environ.get("LAB_BASE_URL", "http://127.0.0.1:5001/api/v1")
TOKEN = os.environ.get("VENDOR_TOKEN")
PRODUCT_ID = int(os.environ.get("PRODUCT_ID", "2"))

if not TOKEN:
    sys.exit("Set VENDOR_TOKEN to a vendor/admin access_token first (see module docstring).")

HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}


def race_stale_version():
    print("=== Test 1: 10 concurrent requests, same stale version, distinct Idempotency-Keys ===")
    baseline = requests.get(f"{BASE}/products/{PRODUCT_ID}", headers=HEADERS, timeout=10).json()
    version = baseline["version"]

    def attempt(i):
        return requests.patch(
            f"{BASE}/products/{PRODUCT_ID}/price",
            headers={**HEADERS, "Idempotency-Key": f"race-{i}"},
            json={"price": round(11.0 + i, 2), "version": version},
            timeout=10,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(attempt, range(10)))
    statuses = [r.status_code for r in results]
    print("status codes:", statuses)
    assert statuses.count(200) == 1, f"expected exactly one 200, got {statuses.count(200)}"
    assert statuses.count(409) == 9, f"expected exactly nine 409s, got {statuses.count(409)}"
    final = requests.get(f"{BASE}/products/{PRODUCT_ID}", headers=HEADERS, timeout=10).json()
    print("PASS: exactly one writer won the race; final version:", final["version"])
    return final["version"]


def race_duplicate_idempotency_key(version):
    print()
    print("=== Test 2: 10 concurrent requests, SAME Idempotency-Key (duplicate submit) ===")

    def attempt(_i):
        return requests.patch(
            f"{BASE}/products/{PRODUCT_ID}/price",
            headers={**HEADERS, "Idempotency-Key": "dup-key-evidence-1"},
            json={"price": 99.99, "version": version},
            timeout=10,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(attempt, range(10)))
    statuses = [r.status_code for r in results]
    bodies = [r.json() for r in results]
    versions_returned = {b.get("version") for b in bodies if "version" in b}
    print("status codes:", statuses)
    print("distinct versions returned to callers:", versions_returned)
    assert all(s == 200 for s in statuses)
    assert len(versions_returned) == 1, "callers disagree on the resulting version -- replay failed"
    final = requests.get(f"{BASE}/products/{PRODUCT_ID}", headers=HEADERS, timeout=10).json()
    assert final["version"] == version + 1, "idempotency FAILED: price applied more than once"
    print("PASS: exactly one price change applied despite 10 concurrent duplicate requests")


if __name__ == "__main__":
    v = race_stale_version()
    race_duplicate_idempotency_key(v)
