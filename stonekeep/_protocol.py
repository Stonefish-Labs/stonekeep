"""JSON protocol for Guardian <-> Client communication.

All messages are length-prefixed JSON over a transport channel
(Unix domain socket, TCP, or TLS):
  [4 bytes big-endian length][JSON payload]

Authenticated actions require `profile_name` and `token` fields.

Actions:
  get_config   -- returns non-sensitive entries (profile_name + token required)
  get_secret   -- returns a single sensitive value (profile_name + token + key required)
  set_entry    -- writes a key-value pair (profile_name + token + key required)
  delete_entry -- removes a key (profile_name + token + key required)
  set_config   -- replaces all non-sensitive entries (profile_name + token + data required)
  ping         -- health check (no auth)
  shutdown     -- stop Guardian (no auth)
"""

import json
import struct
from typing import Any

PROTOCOL_VERSION = 1
HEADER_SIZE = 4
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB

# Request actions
ACTION_GET_CONFIG = "get_config"
ACTION_GET_SECRET = "get_secret"
ACTION_SET_ENTRY = "set_entry"
ACTION_SET_CONFIG = "set_config"
ACTION_DELETE_ENTRY = "delete_entry"
ACTION_PING = "ping"
ACTION_SHUTDOWN = "shutdown"

# Response statuses
STATUS_OK = "ok"
STATUS_ERROR = "error"

# Error codes
ERR_NOT_FOUND = "not_found"
ERR_ACCESS_DENIED = "access_denied"
ERR_INVALID_TOKEN = "invalid_token"
ERR_TOKEN_EXPIRED = "token_expired"
ERR_WRITE_DENIED = "write_denied"
ERR_TIMEOUT = "timeout"
ERR_NOT_INITIALIZED = "not_initialized"
ERR_INVALID_ACTION = "invalid_action"
ERR_MALFORMED_REQUEST = "malformed_request"
ERR_INTERNAL = "internal_error"


def encode_message(data: dict[str, Any]) -> bytes:
    """Encode a dict as a length-prefixed JSON message."""
    payload = json.dumps(data).encode("utf-8")
    header = struct.pack(">I", len(payload))
    return header + payload


def decode_message(raw: bytes) -> dict[str, Any]:
    """Decode a length-prefixed JSON message."""
    return json.loads(raw.decode("utf-8"))


def make_request(
    action: str,
    profile_name: str = "",
    key: str = "",
    token: str = "",
    **kwargs: Any,
) -> dict[str, Any]:
    """Build a request message."""
    req: dict[str, Any] = {"action": action}
    if profile_name:
        req["profile_name"] = profile_name
    if key:
        req["key"] = key
    if token:
        req["token"] = token
    req.update(kwargs)
    return req


def make_response(
    status: str,
    data: Any = None,
    error: str = "",
    message: str = "",
) -> dict[str, Any]:
    """Build a response message."""
    resp: dict[str, Any] = {"status": status}
    if data is not None:
        resp["data"] = data
    if error:
        resp["error"] = error
    if message:
        resp["message"] = message
    return resp
