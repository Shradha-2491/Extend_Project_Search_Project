import os
import secrets
import logging
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent

LAB_SECRET_KEY = os.environ.get("LAB_SECRET_KEY")
if not LAB_SECRET_KEY:
    logging.warning("LAB_SECRET_KEY is not set -- using a random, process-lifetime secret key.")
LAB_SECRET_KEY = LAB_SECRET_KEY or secrets.token_hex(32)

# Symmetric key used to encrypt MFA secrets at rest (Fernet, urlsafe base64, 32 bytes).
LAB_ENC_KEY = os.environ.get("LAB_ENC_KEY")

LAB_HTTPS = os.environ.get("LAB_HTTPS") == "1"

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
# Separate OAuth client registered as an Android/native client (no client secret --
# native apps use PKCE instead). Kept distinct from the web client id so a stolen
# mobile id_token audience can never be replayed against the web flow or vice versa.
GOOGLE_CLIENT_ID_MOBILE = os.environ.get("GOOGLE_CLIENT_ID_MOBILE", "")

ADMIN_EMAILS = {
    e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()
}

DB = BASE_DIR / "lab.db"
AUDIT_DB_PATH = BASE_DIR / "audit.db"
AUDIT_FLATFILE_PATH = BASE_DIR / "audit.log"
MAIL_OUTBOX_DIR = BASE_DIR / "mail_outbox"

JWT_ISSUER = "product-search-lab"
JWT_ACCESS_TTL_SECONDS = 15 * 60
JWT_REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60
JWT_PENDING_MFA_TTL_SECONDS = 5 * 60

MFA_ISSUER_NAME = "ProductSearchLab"
MFA_MAX_FAILED_ATTEMPTS = 5
MFA_LOCKOUT_SECONDS = 5 * 60

LOGIN_MAX_FAILED_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 5 * 60

PASSWORD_RESET_TTL_SECONDS = 15 * 60
