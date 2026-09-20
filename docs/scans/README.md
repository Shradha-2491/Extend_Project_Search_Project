# Scan reports and what they mean

Raw tool output is kept in this folder for reproducibility, but per the
assignment rules ("do not submit too many scanner screenshots... marks focus
on implemented security controls and testing"), this file is the part that
should actually be read.

## Dependency vulnerabilities (`pip-audit`)

- **Before fix**: `pip_audit_raw` run found 10 known CVEs, all in one
  package: `cryptography==43.0.3`, pulled in by our own `requirements.txt`
  pin of `cryptography>=41.0,<44.0`. The upper bound was stopping pip from
  ever installing a fixed release.
- **Fix applied**: `requirements.txt` now pins `cryptography>=44.0.1` (the
  first release with all of PYSEC-2026-1284 / -2141 / -35 / -3553 / -3554
  and GHSA-537c-gmf6-5ccf fixed); the venv here was upgraded to 50.0.1.
- **After fix**: `pip_audit_after_fix.txt` — "No known vulnerabilities
  found". `pytest` (17/17) was re-run after the upgrade to confirm no
  regression (see `docs/test-evidence/pytest_output.txt`).
- **OWASP mapping**: A06 - Vulnerable and Outdated Components.

## Static analysis (`bandit`)

Full output: `bandit_report.txt`. Five findings remain; none require a code
change:

| # | Finding | File | Verdict |
|---|---|---|---|
| 1 | B608 possible SQL injection | `app.py:146` (`vulnerable_login`) | **Intentional.** This is the original OWASP-injection teaching route, kept deliberately vulnerable as the "before" side of the Injection control's evidence (see `owasp-control-table.md`, A03 row). It never establishes a session regardless of query result, so it cannot be used to actually log in as anyone. |
| 2 | B608 possible SQL injection | `app.py:215` (`vulnerable_search`) | **Intentional**, same reasoning — the teaching "before" example; `search-secure` next to it is the parameterized "after". |
| 3 | B404 subprocess import | `db.py` | **Accepted, low risk.** Only used once, to run `chattr +a` on the audit log file (see #4/#5 below) — no other use of `subprocess` in the codebase. |
| 4/5 | B608 on `products.py` / `users_admin.py` UPDATE statements | (fixed via `# nosec` with inline justification) | **False positive, explained inline.** Both f-strings only ever splice in hardcoded `"<column> = ?"` fragments from a fixed allowlist chosen in the same function — never user input — and every actual value is still bound as a `?` parameter. Bandit's pattern-matcher can't see that distinction from the f-string shape alone. |
| 6/7 | B105 "hardcoded password" | `templates.py` (`PASSWORD_RESET_*_BODY`) | **False positive.** Bandit's heuristic triggers on the variable *name* containing "password"; the value is an HTML template string, not a credential. |

**Real fix applied as a result of this scan**: `db.py`'s `chattr` call
previously invoked the bare command name (`["chattr", "+a", path]`), which
Bandit flagged as B607 (partial executable path — vulnerable to PATH
manipulation). It now resolves the absolute path with `shutil.which()` first
and skips the OS-level hardening step with a warning if `chattr` isn't
found, instead of trusting `$PATH`. Confirmed fixed: B607 no longer appears
in `bandit_report.txt`.

**OWASP mapping**: A03 - Injection (rows 1/2/4/5, both the deliberate
teaching example and the confirmed-safe pattern elsewhere), A05 - Security
Misconfiguration (row 3/the PATH-resolution fix).

## SBOM

- `docs/sbom/backend-sbom.json` — real CycloneDX SBOM generated with
  `pip-audit --format=cyclonedx-json` against the final `requirements.txt`
  (31 components, 0 known vulnerabilities as of the scan above).
- `docs/sbom/mobile-sbom.json` — hand-authored CycloneDX SBOM listing the
  Android app's declared dependencies from `gradle/libs.versions.toml`
  (Gradle could not be run in the environment that authored this project —
  see `docs/mobile-security-checklist.md` §5 for the one command that
  regenerates a tool-verified version once you have Android Studio/JDK).

## Mobile scans

Static/dynamic scans of the actual APK (`apktool`/`jadx` secret search,
`aapt` debuggable check, EncryptedSharedPreferences verification, mitmproxy
TLS-pinning demonstration) require building and signing a real APK and
running it on a device/emulator, which this sandbox cannot do (no JDK/
Android SDK). Reproducible step-by-step commands and pass/fail criteria for
each are in `docs/mobile-security-checklist.md`; run them once in Android
Studio and drop the output files into `docs/scans/mobile/`.
