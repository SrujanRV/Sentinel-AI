"""FastAPI dependencies shared across routes."""

import secrets

from fastapi import Depends, Header, HTTPException, status

from app.config import Settings, get_settings


def verify_api_key(
    x_api_key: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    """Timing-safe X-API-Key header verification.

    Raises HTTP 401 if the header is absent or the key does not match
    any entry in settings.api_key_set.  secrets.compare_digest is used
    to prevent timing-oracle attacks.
    """
    if x_api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    valid_keys = settings.api_key_set
    # Compare against every valid key to avoid short-circuiting on index.
    authenticated = any(secrets.compare_digest(x_api_key, k) for k in valid_keys)
    if not authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
