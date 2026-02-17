"""Stonekeep - Profile-based configuration and secrets for AI agents.

Consumer API:
    from stonekeep import Vault

    vault = Vault(profile="discord-webhook")
    config = vault.get_config()
    api_key = vault.get_secret("api_key")

For tools that need write access:
    from stonekeep import WritableVault

    vault = WritableVault(profile="my-oauth-api")
    vault.set_secret("access_token", new_token)

Transport configuration (STONEKEEP_URL env var or url= parameter):
    unix://~/.stonekeep/guardian.sock  (default, local)
    tcp://host:port                    (unencrypted TCP, warn if non-loopback)
    tls://host:port                    (TLS-encrypted TCP)

Backend selection (STONEKEEP_MODE env var):
    unset / "production"  ->  Guardian service (encrypted, secure default)
    "dev"                 ->  Flat JSON files (~/.config/stonekeep/profiles/)

In production, these classes communicate with the Guardian service over
a configurable transport channel. The Guardian holds the master encryption
key and enforces token-based authentication and per-key approval policies.

In dev mode, profiles are plain JSON files with no encryption and no
Guardian. Tokens are accepted but ignored.
"""

import os

__version__ = "0.2.0"

from .exceptions import (
    StonekeepError,
    ProfileNotFoundError,
    AccessDeniedError,
    InvalidTokenError,
    WriteDeniedError,
    VaultNotInitializedError,
    GuardianConnectionError,
    GuardianTimeoutError,
    CryptoError,
    MasterKeyError,
)

_mode = os.environ.get("STONEKEEP_MODE", "").strip().lower()

if _mode == "dev":
    from ._devbackend import Vault, WritableVault, vault
else:
    from ._client import Vault, WritableVault, vault


__all__ = [
    "Vault",
    "WritableVault",
    "vault",
    "StonekeepError",
    "ProfileNotFoundError",
    "AccessDeniedError",
    "InvalidTokenError",
    "WriteDeniedError",
    "VaultNotInitializedError",
    "GuardianConnectionError",
    "GuardianTimeoutError",
    "CryptoError",
    "MasterKeyError",
]
