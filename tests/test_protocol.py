"""Tests for the wire protocol module."""

import json
import struct
import pytest

from stonekeep._protocol import (
    PROTOCOL_VERSION,
    HEADER_SIZE,
    MAX_MESSAGE_SIZE,
    encode_message,
    decode_message,
    make_request,
    make_response,
    STATUS_OK,
    STATUS_ERROR,
)


class TestProtocolConstants:
    def test_version_is_one(self):
        assert PROTOCOL_VERSION == 1

    def test_header_size(self):
        assert HEADER_SIZE == 4

    def test_max_message_size(self):
        assert MAX_MESSAGE_SIZE == 10 * 1024 * 1024


class TestEncodeDecodeMessage:
    def test_roundtrip(self):
        data = {"action": "ping"}
        encoded = encode_message(data)
        # First 4 bytes are the length header
        length = struct.unpack(">I", encoded[:4])[0]
        payload = encoded[4:]
        assert len(payload) == length
        decoded = decode_message(payload)
        assert decoded == data

    def test_roundtrip_complex(self):
        data = {
            "action": "get_secret",
            "profile_name": "test",
            "key": "api_key",
            "token": "skt_abc123",
        }
        encoded = encode_message(data)
        payload = encoded[4:]
        decoded = decode_message(payload)
        assert decoded == data

    def test_unicode(self):
        data = {"key": "value with unicode: \u2603"}
        encoded = encode_message(data)
        payload = encoded[4:]
        decoded = decode_message(payload)
        assert decoded == data


class TestMakeRequest:
    def test_minimal(self):
        req = make_request("ping")
        assert req == {"action": "ping"}

    def test_with_profile_and_token(self):
        req = make_request("get_config", profile_name="test", token="skt_abc")
        assert req == {"action": "get_config", "profile_name": "test", "token": "skt_abc"}

    def test_with_key(self):
        req = make_request("get_secret", profile_name="test", key="api_key", token="skt_abc")
        assert req["key"] == "api_key"

    def test_empty_strings_omitted(self):
        req = make_request("ping", profile_name="", token="")
        assert "profile_name" not in req
        assert "token" not in req

    def test_extra_kwargs(self):
        req = make_request("set_entry", value="secret", sensitive=True)
        assert req["value"] == "secret"
        assert req["sensitive"] is True


class TestMakeResponse:
    def test_ok(self):
        resp = make_response(STATUS_OK, data={"key": "val"})
        assert resp == {"status": "ok", "data": {"key": "val"}}

    def test_error(self):
        resp = make_response(STATUS_ERROR, error="not_found", message="Profile not found")
        assert resp["status"] == "error"
        assert resp["error"] == "not_found"
        assert resp["message"] == "Profile not found"

    def test_no_optional_fields(self):
        resp = make_response(STATUS_OK)
        assert resp == {"status": "ok"}
