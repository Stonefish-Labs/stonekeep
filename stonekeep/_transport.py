"""Transport abstraction for Stonekeep client.

Supports three transport schemes:
  unix:///path/to/socket  -- Unix domain socket (default, local only)
  tcp://host:port         -- TCP without TLS (warn if non-loopback)
  tls://host:port         -- TCP with TLS (Python stdlib ssl module)

URL resolution order:
  1. Explicit url= parameter to Vault constructor
  2. STONEKEEP_URL environment variable
  3. Default: unix://~/.stonekeep/guardian.sock

Zero external dependencies -- uses only Python stdlib.
"""

import os
import socket
import ssl
import warnings
from typing import Optional
from urllib.parse import urlparse

DEFAULT_SOCKET_PATH = os.path.join(
    os.path.expanduser("~"), ".stonekeep", "guardian.sock"
)
DEFAULT_PORT = 9700
DEFAULT_URL = f"unix://{DEFAULT_SOCKET_PATH}"

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def resolve_url(url: Optional[str] = None) -> str:
    """Resolve the Guardian URL from parameter, env var, or default.

    Resolution order:
      1. Explicit url parameter (if non-empty)
      2. STONEKEEP_URL environment variable
      3. Default unix socket path
    """
    if url:
        return url
    env_url = os.environ.get("STONEKEEP_URL", "").strip()
    if env_url:
        return env_url
    return DEFAULT_URL


def parse_url(url: str) -> dict:
    """Parse a Guardian URL into transport parameters.

    Returns a dict with:
      scheme: "unix", "tcp", or "tls"
      path: socket file path (unix only)
      host: hostname or IP (tcp/tls only)
      port: port number (tcp/tls only)

    Raises ValueError for unsupported schemes.
    """
    if url.startswith("unix://"):
        path = url[7:]
        if not path or path == "/":
            path = DEFAULT_SOCKET_PATH
        path = os.path.expanduser(path)
        return {"scheme": "unix", "path": path}

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("tcp", "tls"):
        raise ValueError(
            f"Unsupported URL scheme: {scheme!r}. "
            "Use unix://, tcp://, or tls://"
        )

    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or DEFAULT_PORT
    return {"scheme": scheme, "host": host, "port": port}


def connect(
    params: dict,
    timeout: float = 30.0,
    ca_cert: Optional[str] = None,
) -> socket.socket:
    """Create a connected socket based on transport parameters.

    For unix://, returns a connected AF_UNIX socket.
    For tcp://, returns a connected AF_INET socket (warns for non-loopback).
    For tls://, returns a connected AF_INET socket wrapped with TLS.

    The ca_cert parameter (or STONEKEEP_CA_CERT env var) specifies the
    CA certificate file for TLS server verification.
    """
    scheme = params["scheme"]

    if scheme == "unix":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(params["path"])
        return sock

    host = params["host"]
    port = params["port"]

    if scheme == "tcp":
        if host not in _LOOPBACK_HOSTS:
            warnings.warn(
                f"Connecting to Guardian over unencrypted TCP at {host}:{port}. "
                "Use tls:// for non-loopback connections.",
                UserWarning,
                stacklevel=3,
            )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return sock

    if scheme == "tls":
        ca_cert = (
            ca_cert
            or os.environ.get("STONEKEEP_CA_CERT", "").strip()
            or None
        )
        ctx = ssl.create_default_context()
        if ca_cert:
            ctx.load_verify_locations(ca_cert)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        sock.connect((host, port))
        return sock

    raise ValueError(f"Unsupported transport scheme: {scheme!r}")


def is_local(params: dict) -> bool:
    """Return True if the transport is a local Unix socket."""
    return params["scheme"] == "unix"
