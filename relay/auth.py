"""HTTP bearer authentication. Token creation and storage live in the domain."""
import hashlib
import re

_BEARER = re.compile(r'Bearer ([A-Za-z0-9_-]{20,128})')


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def bearer_token(header):
    """Return the token from an Authorization header, or None if absent or malformed."""
    match = _BEARER.fullmatch(header or '')
    return match.group(1) if match else None


def authenticate(domain, header):
    """Return the principal {name, role} for a valid active token, else None."""
    token = bearer_token(header)
    return domain.lookup(hash_token(token)) if token else None
