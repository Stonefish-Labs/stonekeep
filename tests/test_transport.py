"""Tests for the transport abstraction layer."""

import os
import pytest

from stonekeep._transport import (
    resolve_url,
    parse_url,
    is_local,
    DEFAULT_SOCKET_PATH,
    DEFAULT_PORT,
    DEFAULT_URL,
)


class TestParseUrl:
    def test_unix_default(self):
        result = parse_url("unix://")
        assert result["scheme"] == "unix"
        assert result["path"] == DEFAULT_SOCKET_PATH

    def test_unix_explicit_path(self):
        result = parse_url("unix:///tmp/test.sock")
        assert result["scheme"] == "unix"
        assert result["path"] == "/tmp/test.sock"

    def test_unix_tilde_expansion(self):
        result = parse_url("unix://~/.stonekeep/guardian.sock")
        assert result["scheme"] == "unix"
        assert "~" not in result["path"]
        assert result["path"].endswith(".stonekeep/guardian.sock")

    def test_tcp_host_port(self):
        result = parse_url("tcp://10.0.0.5:9700")
        assert result["scheme"] == "tcp"
        assert result["host"] == "10.0.0.5"
        assert result["port"] == 9700

    def test_tcp_default_port(self):
        result = parse_url("tcp://myhost")
        assert result["scheme"] == "tcp"
        assert result["host"] == "myhost"
        assert result["port"] == DEFAULT_PORT

    def test_tcp_localhost(self):
        result = parse_url("tcp://127.0.0.1:8080")
        assert result["scheme"] == "tcp"
        assert result["host"] == "127.0.0.1"
        assert result["port"] == 8080

    def test_tls_host_port(self):
        result = parse_url("tls://guardian.internal:9700")
        assert result["scheme"] == "tls"
        assert result["host"] == "guardian.internal"
        assert result["port"] == 9700

    def test_tls_default_port(self):
        result = parse_url("tls://secrets.example.com")
        assert result["scheme"] == "tls"
        assert result["host"] == "secrets.example.com"
        assert result["port"] == DEFAULT_PORT

    def test_unsupported_scheme(self):
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            parse_url("http://example.com")

    def test_unsupported_scheme_ws(self):
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            parse_url("ws://example.com")


class TestResolveUrl:
    def test_explicit_url(self):
        assert resolve_url("tcp://myhost:9700") == "tcp://myhost:9700"

    def test_explicit_overrides_env(self, monkeypatch):
        monkeypatch.setenv("STONEKEEP_URL", "tcp://envhost:9700")
        assert resolve_url("tcp://explicit:9700") == "tcp://explicit:9700"

    def test_env_var(self, monkeypatch):
        monkeypatch.setenv("STONEKEEP_URL", "tls://envhost:9700")
        assert resolve_url() == "tls://envhost:9700"

    def test_env_var_stripped(self, monkeypatch):
        monkeypatch.setenv("STONEKEEP_URL", "  tcp://host:9700  ")
        assert resolve_url() == "tcp://host:9700"

    def test_default(self, monkeypatch):
        monkeypatch.delenv("STONEKEEP_URL", raising=False)
        result = resolve_url()
        assert result == DEFAULT_URL
        assert result.startswith("unix://")

    def test_empty_env_uses_default(self, monkeypatch):
        monkeypatch.setenv("STONEKEEP_URL", "")
        result = resolve_url()
        assert result == DEFAULT_URL


class TestIsLocal:
    def test_unix_is_local(self):
        assert is_local({"scheme": "unix", "path": "/tmp/test.sock"}) is True

    def test_tcp_not_local(self):
        assert is_local({"scheme": "tcp", "host": "127.0.0.1", "port": 9700}) is False

    def test_tls_not_local(self):
        assert is_local({"scheme": "tls", "host": "host", "port": 9700}) is False
