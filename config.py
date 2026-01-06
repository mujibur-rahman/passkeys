import os
from webauthn import base64url_to_bytes
import secrets

# Local dev defaults
RP_ID = os.getenv("RP_ID", "localhost")
ORIGIN = os.getenv("ORIGIN", "http://localhost:8000")
RP_NAME = os.getenv("RP_NAME", "localhost")

SESSION_SECRET = os.getenv("SESSION_SECRET", "dev-only-change-me")
DB_PATH = os.getenv("DB_PATH", "webauthn.sqlite3")

CHALLENGE_TTL_SECONDS = int(os.getenv("CHALLENGE_TTL_SECONDS", "120"))

# AES-256-GCM key in base64url (no padding) for credential encryption at rest.
ENC_KEY_B64URL = os.getenv("CRED_ENC_KEY_B64URL", "").strip()
if ENC_KEY_B64URL:
    ENC_KEY = base64url_to_bytes(ENC_KEY_B64URL)
else:
    # Dev fallback: volatile key; DB becomes unreadable after restart. Not for prod.
    ENC_KEY = secrets.token_bytes(32)

if len(ENC_KEY) != 32:
    raise RuntimeError("CRED_ENC_KEY_B64URL must decode to exactly 32 bytes.")