"""TOTP-based MFA (RFC 6238), enforced for every local-password account and
for Google-authenticated accounts alike -- see security.py's Google flow,
which routes through the same MFA gate before issuing a full session/token."""
import io
import base64

import pyotp
import qrcode

import config


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, account_email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=account_email, issuer_name=config.MFA_ISSUER_NAME
    )


def verify_code(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    # valid_window=1 tolerates +/-30s of clock drift between device and server.
    return totp.verify(code.strip(), valid_window=1)


def qr_data_uri(uri: str) -> str:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"
