"""Dev backend -- flat JSON profile storage for development.

Activated when STONEKEEP_MODE=dev. Profiles are plain JSON files on
disk -- no Guardian, no encryption, no SQLite.

Storage layout:
    ~/.config/stonekeep/profiles/<name>.json

Each file is a flat dict of string key-value pairs:
    {"webhook_url": "https://...", "bot_name": "Agent", "api_key": "sk-..."}

In dev there's no sensitive/non-sensitive distinction. get_config()
returns everything, get_secret() returns any key.

Security hardening (best-effort for a dev-only backend):
    - Profile names are validated to prevent path traversal.
    - Files are written atomically (temp + rename) and chmod 0600.
    - The profiles directory is created / enforced as 0700.
"""

import json
import os
import re
import tempfile
import warnings
from pathlib import Path

from .exceptions import (
    StonekeepError,
    ProfileNotFoundError,
    AccessDeniedError,
    WriteDeniedError,
)


# -- Profile name validation --

_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _validate_profile_name(name: str) -> None:
    """Reject profile names that could escape the profiles directory.

    Allowed characters: ASCII letters, digits, hyphens, underscores, dots.
    Must start with a letter or digit (blocks ".." and hidden files).
    """
    if not _SAFE_NAME_RE.match(name):
        raise StonekeepError(
            f"Invalid profile name '{name}'. "
            "Names must start with a letter or digit and contain only "
            "letters, digits, hyphens, underscores, and dots."
        )


# -- Configuration --

_DEFAULT_BASE = Path.home() / ".config" / "stonekeep" / "profiles"

_DIR_MODE = 0o700   # rwx------
_FILE_MODE = 0o600  # rw-------


def _base_dir() -> Path:
    """Return the profiles directory, honouring STONEKEEP_DEV_DIR override."""
    override = os.environ.get("STONEKEEP_DEV_DIR")
    if override:
        return Path(override)
    return _DEFAULT_BASE


def _ensure_dir(directory: Path) -> None:
    """Create the profiles directory if needed and enforce 0700 permissions."""
    directory.mkdir(parents=True, exist_ok=True)
    try:
        current = directory.stat().st_mode & 0o777
        if current != _DIR_MODE:
            directory.chmod(_DIR_MODE)
    except OSError:
        pass  # best-effort; may fail on some filesystems


# -- Internal helpers --

def _profile_path(name: str) -> Path:
    _validate_profile_name(name)
    base = _base_dir()
    resolved = (base / f"{name}.json").resolve()
    # Belt-and-suspenders: ensure the resolved path is under the base dir.
    if not str(resolved).startswith(str(base.resolve())):
        raise StonekeepError(
            f"Profile name '{name}' resolves outside the profiles directory."
        )
    return resolved


def _load(name: str) -> dict[str, str]:
    path = _profile_path(name)
    if not path.is_file():
        raise ProfileNotFoundError(name)
    return json.loads(path.read_text(encoding="utf-8"))


def _save(name: str, data: dict[str, str]) -> None:
    path = _profile_path(name)
    _ensure_dir(path.parent)

    # Atomic write: create a temp file in the same directory, write to it,
    # set permissions, then atomically replace the target.
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        os.fchmod(fd, _FILE_MODE)
        os.write(fd, (json.dumps(data, indent=2) + "\n").encode("utf-8"))
        os.close(fd)
        fd = -1  # mark as closed so the except block doesn't double-close
        os.replace(tmp, path)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        # Clean up the temp file on failure.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# -- Profile resolution --

def _resolve_profile(profile: str) -> str:
    """Resolve a profile name.

    Resolution order:
      1. Explicit profile parameter (non-empty)
      2. STONEKEEP_PROFILE env var
      3. Error
    """
    if profile:
        return profile
    env_profile = os.environ.get("STONEKEEP_PROFILE", "").strip()
    if env_profile:
        return env_profile
    raise StonekeepError(
        "No profile specified. Pass profile= or set STONEKEEP_PROFILE env var."
    )


# -- Public API --

class Vault:
    """Read-only vault client (dev backend).

    Binds to a profile at construction time but does nothing until a
    method is called.  Profile resolution and file I/O are lazy.

    Token, url, and ca_cert are accepted for API compat but ignored
    in dev mode.
    """

    def __init__(
        self,
        profile: str = "",
        *,
        token: str | None = None,
        timeout: float = 30.0,
        url: str | None = None,
        ca_cert: str | None = None,
    ) -> None:
        self._profile = profile
        self._token = token
        self._timeout = timeout

    def get_config(self) -> dict[str, str]:
        """Get all config entries for the profile.

        In dev, everything is returned -- there's no sensitive/non-sensitive
        split.
        """
        return _load(_resolve_profile(self._profile))

    def get_secret(self, key: str) -> str:
        """Get a single secret value from the profile.

        In dev, any key can be fetched -- there's no approval dialog.
        """
        name = _resolve_profile(self._profile)
        data = _load(name)
        if key not in data:
            raise StonekeepError(f"Key '{key}' not found in profile '{name}'")
        return data[key]

    def ping(self) -> bool:
        """Always returns True -- dev backend has no server."""
        return True


class WritableVault(Vault):
    """Vault client with write access (dev backend).

    Opt-in only -- for tools that need to rotate tokens, refresh OAuth
    credentials, or update config/secrets.
    """

    def set_config(self, data: dict[str, str]) -> None:
        """Replace all config entries for the profile wholesale.

        In dev, this overwrites the entire profile JSON file.
        """
        name = _resolve_profile(self._profile)
        _save(name, data)

    def set_secret(self, key: str, value: str) -> None:
        """Write a single secret value to the profile."""
        name = _resolve_profile(self._profile)
        current = _load(name)
        current[key] = value
        _save(name, current)

    def delete_secret(self, key: str) -> None:
        """Delete a key from the profile."""
        name = _resolve_profile(self._profile)
        current = _load(name)
        current.pop(key, None)
        _save(name, current)


# -- Dev mode warning --

warnings.warn(
    "Stonekeep is running in DEV mode. Profiles are stored as plain JSON "
    "files with no encryption or access control. Do not use in production.",
    stacklevel=1,
)

# Default read-only instance.  Resolves profile from STONEKEEP_PROFILE
# env var at call time -- zero side effects at import.
vault = Vault()
