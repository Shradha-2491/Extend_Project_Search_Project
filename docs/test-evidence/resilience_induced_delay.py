"""Resilience / graceful-degradation evidence: an external writer holds the
SQLite write lock on the products table for a few seconds (simulating a slow
or stuck concurrent transaction), while a normal price-update request is in
flight against the live server at the same time.

What this proves: db.connect() opens with `timeout=10`, so SQLite makes the
second writer BLOCK AND WAIT for the lock instead of failing immediately or
reading/writing corrupted state. The request completes successfully once the
artificial delay ends, with the correct final price and no partial update --
i.e. the system degrades gracefully (a slower response) rather than failing
unsafely (silent corruption or an unhandled crash).

If the induced delay exceeds the timeout, the request will instead surface a
clean 500 (sqlite3.OperationalError: database is locked) rather than
corrupting data, which is the same "fail closed, not silently" property this
project applies everywhere else (Google email_verified, CSRF, RBAC).

Run with the backend already running and a vendor/admin token in
VENDOR_TOKEN (same as concurrency_price_race.py).
"""
import os
import sqlite3
import sys
import threading
import time

import requests

BASE = os.environ.get("LAB_BASE_URL", "http://127.0.0.1:5001/api/v1")
TOKEN = os.environ.get("VENDOR_TOKEN")
PRODUCT_ID = int(os.environ.get("PRODUCT_ID", "3"))
DB_PATH = os.environ.get("LAB_DB_PATH", "../lab.db")
HOLD_SECONDS = 3

if not TOKEN:
    sys.exit("Set VENDOR_TOKEN to a vendor/admin access_token first (see module docstring).")

HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}


def hold_write_lock():
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.execute("BEGIN IMMEDIATE")
    con.execute("SELECT 1 FROM products")  # touch the table under the write lock
    print(f"[lock-holder] acquired write lock, holding for {HOLD_SECONDS}s ...")
    time.sleep(HOLD_SECONDS)
    con.commit()
    con.close()
    print("[lock-holder] released write lock")


def main():
    baseline = requests.get(f"{BASE}/products/{PRODUCT_ID}", headers=HEADERS, timeout=20).json()
    version = baseline["version"]

    t = threading.Thread(target=hold_write_lock)
    t.start()
    time.sleep(0.3)  # let the lock-holder actually acquire the lock first

    print("[requester] sending price update while the lock is held ...")
    start = time.monotonic()
    resp = requests.patch(
        f"{BASE}/products/{PRODUCT_ID}/price",
        headers={**HEADERS, "Idempotency-Key": "resilience-evidence-1"},
        json={"price": 77.77, "version": version},
        timeout=20,
    )
    elapsed = time.monotonic() - start
    t.join()

    print(f"[requester] got status {resp.status_code} after waiting {elapsed:.2f}s")
    print("[requester] body:", resp.json())

    assert elapsed >= HOLD_SECONDS - 0.5, "request did not actually wait for the lock"
    assert resp.status_code == 200, "expected the delayed write to eventually succeed cleanly"
    final = requests.get(f"{BASE}/products/{PRODUCT_ID}", headers=HEADERS, timeout=20).json()
    assert final["price"] == 77.77 and final["version"] == version + 1
    print("PASS: request queued behind the held lock and completed correctly -- "
          "no partial write, no corruption, graceful (slower, not broken) degradation.")


if __name__ == "__main__":
    main()
