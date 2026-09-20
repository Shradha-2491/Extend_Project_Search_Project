"""Synthetic mail sink for the classroom environment. There is no SMTP
relay configured (and per the assignment rules, only synthetic test data may
be used) -- password-reset "emails" are written to a local text file instead
of actually being sent, so the flow is fully reproducible offline."""
import re
from datetime import datetime, timezone

import config


def send_mail(to: str, subject: str, body: str) -> str:
    config.MAIL_OUTBOX_DIR.mkdir(exist_ok=True)
    safe_to = re.sub(r"[^a-zA-Z0-9_.@-]", "_", to)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    path = config.MAIL_OUTBOX_DIR / f"{ts}_{safe_to}.txt"
    path.write_text(f"To: {to}\nSubject: {subject}\n\n{body}\n", encoding="utf-8")
    return str(path)
