"""Tests for token discovery: dotenv file parsing, resolution priority."""

import pytest

from stonekeep._client import _load_token_file, _resolve_token, _parse_token_file, StonekeepError


class TestTokenDiscovery:
    def test_load_token_file_dotenv(self, tmp_path, monkeypatch):
        """Parse dotenv-style .stonekeep-token with multiple profiles."""
        project_dir = tmp_path / "myproject"
        sub_dir = project_dir / "src" / "deep"
        sub_dir.mkdir(parents=True)

        token_file = project_dir / ".stonekeep-token"
        token_file.write_text(
            "# tokens for this project\n"
            "discord-webhook=skt_token_discord\n"
            "my-api=skt_token_api\n"
            "\n"
            "# staging profile\n"
            "monitoring=skt_token_mon\n"
        )

        monkeypatch.chdir(sub_dir)
        result = _load_token_file()
        assert result is not None
        assert result["discord-webhook"] == "skt_token_discord"
        assert result["my-api"] == "skt_token_api"
        assert result["monitoring"] == "skt_token_mon"
        assert len(result) == 3

    def test_load_token_file_not_found(self, tmp_path, monkeypatch):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        monkeypatch.chdir(empty_dir)
        result = _load_token_file()
        assert result is None

    def test_resolve_token_explicit(self):
        assert _resolve_token("myprofile", "skt_explicit") == "skt_explicit"

    def test_resolve_token_from_dotenv_file(self, tmp_path, monkeypatch):
        monkeypatch.delenv("STONEKEEP_TOKEN", raising=False)
        token_file = tmp_path / ".stonekeep-token"
        token_file.write_text("my-api=skt_from_file\nother=skt_other\n")
        monkeypatch.chdir(tmp_path)

        assert _resolve_token("my-api") == "skt_from_file"
        assert _resolve_token("other") == "skt_other"

    def test_resolve_token_env_fallback(self, tmp_path, monkeypatch):
        """STONEKEEP_TOKEN is used as fallback if profile not in file."""
        monkeypatch.setenv("STONEKEEP_TOKEN", "skt_from_env")
        monkeypatch.chdir(tmp_path)
        assert _resolve_token("any-profile") == "skt_from_env"

    def test_resolve_token_file_takes_priority_over_env(self, tmp_path, monkeypatch):
        """Token file match for profile takes priority over env var."""
        monkeypatch.setenv("STONEKEEP_TOKEN", "skt_from_env")
        token_file = tmp_path / ".stonekeep-token"
        token_file.write_text("my-api=skt_from_file\n")
        monkeypatch.chdir(tmp_path)

        assert _resolve_token("my-api") == "skt_from_file"

    def test_resolve_token_missing_profile_in_file_uses_env(self, tmp_path, monkeypatch):
        """If profile not in file but env is set, use env."""
        monkeypatch.setenv("STONEKEEP_TOKEN", "skt_from_env")
        token_file = tmp_path / ".stonekeep-token"
        token_file.write_text("other=skt_other\n")
        monkeypatch.chdir(tmp_path)

        assert _resolve_token("missing-profile") == "skt_from_env"

    def test_resolve_token_error(self, monkeypatch, tmp_path):
        monkeypatch.delenv("STONEKEEP_TOKEN", raising=False)
        monkeypatch.chdir(tmp_path)
        with pytest.raises(StonekeepError, match="No token found"):
            _resolve_token("missing-profile")

    def test_parse_token_file_comments_and_blanks(self, tmp_path):
        """Comments and blank lines are ignored."""
        token_file = tmp_path / "tokens"
        token_file.write_text(
            "# this is a comment\n"
            "\n"
            "profile-a=token-a\n"
            "  # indented comment\n"
            "profile-b=token-b\n"
            "\n"
        )

        result = _parse_token_file(str(token_file))
        assert result == {"profile-a": "token-a", "profile-b": "token-b"}
