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
"""

__version__ = "0.3.0"

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
