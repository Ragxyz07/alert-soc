"""Password hashing and in-memory demo tokens."""
import hashlib, hmac, secrets
TOKENS = {}

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 180000).hex()
    return f"pbkdf2_sha256${salt}${digest}"

def verify_password(password, encoded):
    try:
        scheme, salt, expected = encoded.split("$")
        return scheme == "pbkdf2_sha256" and hmac.compare_digest(hash_password(password, salt).split("$")[-1], expected)
    except (ValueError, AttributeError): return False

def issue_token(username):
    token = secrets.token_urlsafe(32); TOKENS[token] = username; return token
