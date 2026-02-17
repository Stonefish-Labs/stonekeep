"""Zero-dependency client for Stonekeep Guardian service.

This file uses ONLY Python standard library modules. It can be vendored
as a single file into any project without installing stonekeep.

Usage:
    from stonekeep import Vault

    vault = Vault(profile="discord-webhook")
    config = vault.get_config()
    api_key = vault.get_secret("api_key")

Transport configuration:
    vault = Vault(profile="...", url="tls://guardian.internal:9700")
    # or via STONEKEEP_URL environment variable

    Supported URL schemes:
      unix:///path/to/socket  (default: ~/.stonekeep/guardian.sock)
      tcp://host:port         (unencrypted, warns for non-loopback)
      tls://host:port         (TLS-encrypted, CA cert via ca_cert= or STONEKEEP_CA_CERT)

Token resolution per profile:
    1. Explicit token= parameter
    2. Look up profile key in .stonekeep-token file (walk up from cwd)
    3. STONEKEEP_TOKEN env var (single-token fallback)
    4. Error
"""

import json
import os
import socket
import struct
import subprocess
import sys
import time

# Protocol constants (duplicated here for zero-dep vendorability)
_HEADER_SIZE = 4
_MAX_MSG = 10 * 1024 * 1024

# Try importing from the package; fall back to inline constants for vendored use
try:
    from ._protocol import HEADER_SIZE as _HEADER_SIZE, MAX_MESSAGE_SIZE as _MAX_MSG
except ImportError:
    pass

# Paths
_VAULT_DIR = os.path.join(os.path.expanduser("~"), ".stonekeep")
_SOCKET_PATH = os.path.join(_VAULT_DIR, "guardian.sock")
_PID_PATH = os.path.join(_VAULT_DIR, "guardian.pid")

# Token file name for directory-based discovery
_TOKEN_FILENAME = ".stonekeep-token"


# -- Exceptions (self-contained for vendorability) --

class StonekeepError(Exception):
    pass

class ProfileNotFoundError(StonekeepError):
    pass

class AccessDeniedError(StonekeepError):
    pass

class InvalidTokenError(StonekeepError):
    pass

class WriteDeniedError(StonekeepError):
    pass

class GuardianConnectionError(StonekeepError):
    pass

class GuardianTimeoutError(StonekeepError):
    pass


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


# -- Token resolution --

def _resolve_token(profile: str, token: str | None = None) -> str:
    """Resolve a token for the given profile.

    Resolution order:
      1. Explicit token parameter
      2. Look up profile key in .stonekeep-token file (walk up from cwd)
      3. STONEKEEP_TOKEN env var (single-token fallback)
      4. Error
    """
    if token:
        return token

    token_map = _load_token_file()
    if token_map and profile in token_map:
        return token_map[profile]

    env_token = os.environ.get("STONEKEEP_TOKEN", "").strip()
    if env_token:
        return env_token

    raise StonekeepError(
        f"No token found for profile '{profile}'. "
        f"Pass token= parameter, add '{profile}=<token>' to .stonekeep-token, "
        f"or set STONEKEEP_TOKEN env var."
    )


def _load_token_file() -> dict[str, str] | None:
    """Walk up from cwd looking for .stonekeep-token and parse it as dotenv.

    Format: one profile=token per line. Lines starting with # are comments.
    Returns dict of {profile: token} or None if no file found.
    """
    current = os.path.abspath(os.getcwd())

    while True:
        token_path = os.path.join(current, _TOKEN_FILENAME)
        if os.path.isfile(token_path):
            try:
                return _parse_token_file(token_path)
            except OSError:
                pass
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def _parse_token_file(path: str) -> dict[str, str]:
    """Parse a dotenv-style token file into a dict."""
    result = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()
                if key and value:
                    result[key] = value
    return result


# -- Transport --

def _resolve_transport(url: str | None = None, ca_cert: str | None = None) -> dict:
    """Resolve and parse the Guardian transport URL.

    Returns a dict with scheme, path/host/port, and ca_cert.
    """
    try:
        from ._transport import resolve_url, parse_url
        resolved = resolve_url(url)
        params = parse_url(resolved)
    except ImportError:
        # Vendored mode: Unix socket only
        params = {"scheme": "unix", "path": _SOCKET_PATH}

    params["ca_cert"] = ca_cert
    return params


def _connect(params: dict, timeout: float = 30.0) -> socket.socket:
    """Create a connected socket from transport params."""
    try:
        from ._transport import connect
        return connect(params, timeout=timeout, ca_cert=params.get("ca_cert"))
    except ImportError:
        # Vendored mode: Unix socket only
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(params["path"])
        return sock


def _is_local(params: dict) -> bool:
    """Check if the transport is local (Unix socket)."""
    try:
        from ._transport import is_local
        return is_local(params)
    except ImportError:
        return params.get("scheme") == "unix"


# -- Public API --

class Vault:
    """Read-only vault client.

    Binds to a profile at construction time but does nothing until a
    method is called.  Profile and token resolution are lazy.
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
        self._url = url
        self._ca_cert = ca_cert

    def get_config(self) -> dict[str, str]:
        """Get all non-sensitive config entries for the profile.

        Returns a dict of key-value pairs.  No approval dialog.
        """
        profile = _resolve_profile(self._profile)
        resolved_token = _resolve_token(profile, self._token)

        request = {
            "action": "get_config",
            "profile_name": profile,
            "token": resolved_token,
        }

        response = _send_request(
            request, timeout=self._timeout,
            url=self._url, ca_cert=self._ca_cert,
        )
        return response.get("data", {})

    def get_secret(self, key: str) -> str:
        """Get a single sensitive secret value from the profile.

        Triggers a per-key approval dialog on the Guardian side.
        """
        profile = _resolve_profile(self._profile)
        resolved_token = _resolve_token(profile, self._token)

        request = {
            "action": "get_secret",
            "profile_name": profile,
            "key": key,
            "token": resolved_token,
        }

        response = _send_request(
            request, timeout=self._timeout,
            url=self._url, ca_cert=self._ca_cert,
        )
        return response.get("data", "")

    def ping(self) -> bool:
        """Check if the Guardian service is responsive."""
        try:
            response = _send_request(
                {"action": "ping"}, timeout=self._timeout,
                url=self._url, ca_cert=self._ca_cert,
            )
            return response.get("data") == "pong"
        except Exception:
            return False


class WritableVault(Vault):
    """Vault client with write access.

    Opt-in only -- for tools that need to rotate tokens, refresh OAuth
    credentials, or update config/secrets.
    """

    def set_config(self, data: dict[str, str]) -> None:
        """Replace all non-sensitive config entries for the profile wholesale."""
        profile = _resolve_profile(self._profile)
        resolved_token = _resolve_token(profile, self._token)

        request = {
            "action": "set_config",
            "profile_name": profile,
            "data": data,
            "token": resolved_token,
        }

        _send_request(
            request, timeout=self._timeout,
            url=self._url, ca_cert=self._ca_cert,
        )

    def set_secret(self, key: str, value: str) -> None:
        """Write a single secret value to the profile through the Guardian."""
        profile = _resolve_profile(self._profile)
        resolved_token = _resolve_token(profile, self._token)

        request = {
            "action": "set_entry",
            "profile_name": profile,
            "key": key,
            "value": value,
            "sensitive": True,
            "token": resolved_token,
        }

        _send_request(
            request, timeout=self._timeout,
            url=self._url, ca_cert=self._ca_cert,
        )

    def delete_secret(self, key: str) -> None:
        """Delete a key from the profile through the Guardian."""
        profile = _resolve_profile(self._profile)
        resolved_token = _resolve_token(profile, self._token)

        request = {
            "action": "delete_entry",
            "profile_name": profile,
            "key": key,
            "token": resolved_token,
        }

        _send_request(
            request, timeout=self._timeout,
            url=self._url, ca_cert=self._ca_cert,
        )


# Default read-only instance.  Resolves profile from STONEKEEP_PROFILE
# env var at call time -- zero side effects at import.
vault = Vault()


# -- Internal --

def _raise_for_error(response: dict) -> None:
    """Raise the appropriate exception for a Guardian error response."""
    error_code = response.get("error", "")
    message = response.get("message", "")
    if error_code == "not_found":
        raise ProfileNotFoundError(message)
    elif error_code in ("access_denied",):
        raise AccessDeniedError(message)
    elif error_code in ("invalid_token", "token_expired"):
        raise InvalidTokenError(message)
    elif error_code == "write_denied":
        raise WriteDeniedError(message)
    elif error_code == "timeout":
        raise GuardianTimeoutError(message)
    else:
        raise StonekeepError(message or f"Guardian error: {error_code}")


def _send_request(
    request: dict,
    timeout: float = 30.0,
    url: str | None = None,
    ca_cert: str | None = None,
) -> dict:
    """Send a request to the Guardian and return the response."""
    params = _resolve_transport(url, ca_cert)

    # Auto-start Guardian only for local Unix socket transport
    if _is_local(params):
        socket_path = params.get("path", _SOCKET_PATH)
        if not _guardian_is_running(socket_path):
            _start_guardian()
            if not _wait_for_guardian(socket_path, timeout=10.0):
                raise GuardianConnectionError("Failed to start Guardian service")

    try:
        sock = _connect(params, timeout=timeout)
    except (ConnectionRefusedError, FileNotFoundError, ConnectionError) as e:
        if _is_local(params):
            raise GuardianConnectionError("Guardian service is not running")
        raise GuardianConnectionError(
            f"Guardian is not reachable at {url or os.environ.get('STONEKEEP_URL', '')}. "
            "Ensure the Guardian is running at the remote address."
        )

    try:
        payload = json.dumps(request).encode("utf-8")
        header = struct.pack(">I", len(payload))
        sock.sendall(header + payload)

        resp_header = _recv_exact(sock, _HEADER_SIZE)
        resp_len = struct.unpack(">I", resp_header)[0]
        if resp_len > _MAX_MSG:
            raise GuardianConnectionError("Response too large")

        resp_payload = _recv_exact(sock, resp_len)
        response = json.loads(resp_payload.decode("utf-8"))

        if response.get("status") == "error":
            _raise_for_error(response)

        return response

    except socket.timeout:
        raise GuardianTimeoutError(f"Guardian did not respond within {timeout}s")
    except (StonekeepError, ProfileNotFoundError, AccessDeniedError,
            InvalidTokenError, WriteDeniedError, GuardianTimeoutError):
        raise
    except (ConnectionRefusedError, FileNotFoundError, ConnectionError):
        raise GuardianConnectionError("Guardian service is not running or unreachable")
    except Exception as e:
        raise GuardianConnectionError(str(e))
    finally:
        sock.close()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def _guardian_is_running(socket_path: str = _SOCKET_PATH) -> bool:
    if not os.path.exists(socket_path):
        return False
    pid_path = os.path.join(os.path.dirname(socket_path), "guardian.pid")
    if os.path.exists(pid_path):
        try:
            with open(pid_path, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            return False
    return False


def _start_guardian() -> None:
    try:
        subprocess.Popen(
            [sys.executable, "-m", "stonekeep_server.guardian", "--daemon"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as e:
        raise GuardianConnectionError(f"Failed to start Guardian: {e}")


def _wait_for_guardian(socket_path: str = _SOCKET_PATH, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(socket_path):
            time.sleep(0.1)
            return True
        time.sleep(0.1)
    return False
