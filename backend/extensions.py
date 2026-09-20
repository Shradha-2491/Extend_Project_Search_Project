"""Shared Flask extension instances, created unbound so every blueprint can
import and decorate with them, then wired to the app once in app.py."""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)
