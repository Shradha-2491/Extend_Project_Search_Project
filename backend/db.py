import os
import json
import hashlib
import logging
import shutil
import threading
import subprocess
import sqlite3
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash

import config

_log_lock = threading.Lock()
_GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------------------
# Primary application database (users, products, idempotency, refresh tokens)
# ---------------------------------------------------------------------------

def connect():
    # check_same_thread=False + a busy timeout let the threaded dev server
    # (app.run(threaded=True)) serve genuinely concurrent requests against a
    # single SQLite file, which is what the concurrency/race-condition tests
    # rely on. WAL mode lets readers proceed while a writer holds the lock.
    con = sqlite3.connect(config.DB, timeout=10, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def like_escape(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def init_db():
    con = connect()
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("DROP TABLE IF EXISTS products")
    cur.execute("DROP TABLE IF EXISTS idempotency_keys")
    cur.execute("DROP TABLE IF EXISTS refresh_tokens")

    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT NOT NULL CHECK(role IN ('customer', 'vendor', 'admin')),
            auth_provider TEXT NOT NULL DEFAULT 'local',
            active INTEGER NOT NULL DEFAULT 1,
            mfa_secret_enc TEXT,
            mfa_enabled INTEGER NOT NULL DEFAULT 0,
            failed_logins INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            mfa_failed_attempts INTEGER NOT NULL DEFAULT 0,
            mfa_locked_until TEXT,
            reset_token_hash TEXT,
            reset_expires TEXT,
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL CHECK(price >= 0),
            cost REAL NOT NULL DEFAULT 0 CHECK(cost >= 0),
            stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
            active INTEGER NOT NULL DEFAULT 1,
            vendor_id INTEGER NOT NULL REFERENCES users(id),
            version INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            updated_by TEXT NOT NULL
        )
    """)

    # First application of an Idempotency-Key on a price-sensitive endpoint is
    # executed and its response cached here; replays/concurrent duplicates of
    # the same key return the cached response instead of re-applying the change.
    cur.execute("""
        CREATE TABLE idempotency_keys (
            id INTEGER PRIMARY KEY,
            idem_key TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            response_status INTEGER NOT NULL,
            response_body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(idem_key, endpoint)
        )
    """)

    cur.execute("""
        CREATE TABLE refresh_tokens (
            jti TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    now = datetime.now(timezone.utc).isoformat()
    cur.executemany(
        "INSERT INTO users(username, email, password, role, auth_provider, created_at) "
        "VALUES (?, ?, ?, ?, 'local', ?)",
        [
            ("scott", "scott@example.test", generate_password_hash("tiger"), "customer", now),
            ("lalit", "lalit@example.test", generate_password_hash("mohan"), "vendor", now),
            ("admin", "admin@example.test", generate_password_hash("admin-demo-password"), "admin", now),
        ],
    )
    con.commit()

    vendor_id = cur.execute("SELECT id FROM users WHERE username = 'lalit'").fetchone()["id"]
    cur.executemany(
        "INSERT INTO products(name, category, price, cost, stock, active, vendor_id, "
        "version, created_at, updated_at, created_by, updated_by) "
        "VALUES (?, ?, ?, ?, ?, 1, ?, 1, ?, ?, 'lalit', 'lalit')",
        [
            ("Macbook", "Computers", 1500.00, 1100.00, 12, vendor_id, now, now),
            ("Keyboard", "Accessories", 10.00, 4.00, 200, vendor_id, now, now),
            ("Monitor", "Computers", 50.00, 30.00, 40, vendor_id, now, now),
            ("Mouse", "Accessories", 5.00, 2.00, 300, vendor_id, now, now),
        ],
    )
    con.commit()
    con.close()


# ---------------------------------------------------------------------------
# Tamper-evident audit log (hash-chained SQLite table + append-only flat file)
# ---------------------------------------------------------------------------

def audit_connect():
    con = sqlite3.connect(config.AUDIT_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def init_audit_db():
    con = audit_connect()
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            event TEXT NOT NULL,
            details TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL UNIQUE
        )
        """
    )
    con.execute(
        """
        CREATE TRIGGER IF NOT EXISTS audit_log_no_update
        BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is not allowed');
        END
        """
    )
    con.execute(
        """
        CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
        BEFORE DELETE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not allowed');
        END
        """
    )
    con.commit()
    con.close()
    try:
        os.chmod(config.AUDIT_DB_PATH, 0o600)
    except OSError:
        pass


def _try_chattr_append_only(path):
    # Resolved to an absolute path (rather than the bare "chattr" that
    # relies on $PATH) so this can't be tricked into running an attacker-
    # controlled binary placed earlier on the PATH -- fixes Bandit B607.
    # Arguments are a fixed list (no shell=True, no string interpolation of
    # untrusted input), so B603/B404 here are accepted low-risk findings:
    # `path` is our own audit-log file path, never user input.
    chattr = shutil.which("chattr")
    if not chattr:
        logging.warning("chattr not found on PATH -- skipping append-only attribute.")
        return False
    try:
        subprocess.run([chattr, "+a", str(path)], check=True, capture_output=True, timeout=5)  # nosec B603
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        logging.warning(
            f"Could not set the append-only filesystem attribute on {path} ({e}). "
            "This needs Linux, an ext2/3/4-family filesystem, and CAP_LINUX_IMMUTABLE "
            "(root). The audit trail still works, just without this extra OS-level layer."
        )
        return False


def init_audit_flatfile():
    if not config.AUDIT_FLATFILE_PATH.exists():
        config.AUDIT_FLATFILE_PATH.touch()
        try:
            os.chmod(config.AUDIT_FLATFILE_PATH, 0o600)
        except OSError:
            pass
    _try_chattr_append_only(config.AUDIT_FLATFILE_PATH)


def _compute_hash(prev_hash, ts, event, details):
    payload = json.dumps(
        {"ts": ts, "event": event, "details": details, "prev_hash": prev_hash}, sort_keys=True
    )
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


def _last_log_hash(con):
    row = con.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    return row["hash"] if row else _GENESIS_HASH


def log_event(event, **details):
    with _log_lock:
        con = audit_connect()
        prev_hash = _last_log_hash(con)
        ts = datetime.now(timezone.utc).isoformat()
        h = _compute_hash(prev_hash, ts, event, details)
        record = {"ts": ts, "event": event, "details": details, "prev_hash": prev_hash, "hash": h}
        con.execute(
            "INSERT INTO audit_log(ts, event, details, prev_hash, hash) VALUES (?, ?, ?, ?, ?)",
            (ts, event, json.dumps(details, sort_keys=True), prev_hash, h),
        )
        con.commit()
        con.close()
        try:
            with open(config.AUDIT_FLATFILE_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            logging.error(f"Failed to write to append-only flat-file audit log: {e}")


def read_audit_log():
    con = audit_connect()
    rows = con.execute(
        "SELECT ts, event, details, prev_hash, hash FROM audit_log ORDER BY id ASC"
    ).fetchall()
    con.close()
    return [
        {
            "ts": r["ts"],
            "event": r["event"],
            "details": json.loads(r["details"]),
            "prev_hash": r["prev_hash"],
            "hash": r["hash"],
        }
        for r in rows
    ]


def read_flatfile_log():
    if not config.AUDIT_FLATFILE_PATH.exists():
        return []
    entries = []
    with open(config.AUDIT_FLATFILE_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _verify_chain(entries):
    problems = []
    prev_hash = _GENESIS_HASH
    for i, e in enumerate(entries, start=1):
        if e["prev_hash"] != prev_hash:
            problems.append(f"entry {i}: chain link broken (prev_hash does not match)")
        recomputed = _compute_hash(prev_hash, e["ts"], e["event"], e["details"])
        if recomputed != e["hash"]:
            problems.append(f"entry {i}: hash mismatch -- entry was altered")
        prev_hash = e["hash"]
    return problems


def verify_log_integrity():
    db_entries = read_audit_log()
    flatfile_entries = read_flatfile_log()

    problems = [f"[database] {p}" for p in _verify_chain(db_entries)]
    problems += [f"[flat-file] {p}" for p in _verify_chain(flatfile_entries)]

    if len(db_entries) != len(flatfile_entries):
        problems.append(
            f"database has {len(db_entries)} entries but flat-file has "
            f"{len(flatfile_entries)} -- one copy was modified independently of the other"
        )
    else:
        for i, (de, fe) in enumerate(zip(db_entries, flatfile_entries), start=1):
            if de["hash"] != fe["hash"]:
                problems.append(
                    f"entry {i}: database and flat-file copies disagree -- "
                    "one of the two stores has been tampered with"
                )

    return (len(problems) == 0), problems
