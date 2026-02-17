"""Stonekeep exceptions."""


class StonekeepError(Exception):
    """Base exception for all Stonekeep errors."""
    pass


class ProfileNotFoundError(StonekeepError):
    """Raised when a requested profile does not exist."""
    def __init__(self, profile_name: str):
        self.profile_name = profile_name
        super().__init__(f"Profile not found: {profile_name}")


class AccessDeniedError(StonekeepError):
    """Raised when access to a profile is denied (ACL or approval)."""
    def __init__(self, profile_name: str, reason: str = ""):
        self.profile_name = profile_name
        self.reason = reason
        msg = f"Access denied for profile: {profile_name}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)


class InvalidTokenError(StonekeepError):
    """Raised when the provided token is invalid, revoked, or expired."""
    def __init__(self, message: str = ""):
        super().__init__(message or "Invalid or expired token")


class VaultNotInitializedError(StonekeepError):
    """Raised when the vault has not been initialized."""
    def __init__(self):
        super().__init__(
            "Vault not initialized. Run 'stonekeep init' first."
        )


class GuardianConnectionError(StonekeepError):
    """Raised when the Guardian service cannot be reached."""
    def __init__(self, detail: str = ""):
        msg = "Cannot connect to Guardian service"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)


class GuardianTimeoutError(StonekeepError):
    """Raised when waiting for approval times out."""
    def __init__(self, profile_name: str):
        self.profile_name = profile_name
        super().__init__(f"Approval timed out for profile: {profile_name}")


class WriteDeniedError(StonekeepError):
    """Raised when a write operation is denied by policy."""
    def __init__(self, profile_name: str, key: str = ""):
        self.profile_name = profile_name
        self.key = key
        msg = f"Write denied for profile: {profile_name}"
        if key:
            msg += f" (key: {key})"
        super().__init__(msg)


class CryptoError(StonekeepError):
    """Raised on encryption/decryption failures."""
    pass


class MasterKeyError(StonekeepError):
    """Raised when the master key cannot be accessed."""
    def __init__(self, detail: str = ""):
        msg = "Cannot access master encryption key"
        if detail:
            msg += f": {detail}"
        super().__init__(msg)
