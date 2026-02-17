"""Tests for the dev backend (flat JSON profiles)."""

import json
import os
import stat
import pytest

from stonekeep._devbackend import (
    Vault,
    WritableVault,
    _resolve_profile,
    _validate_profile_name,
    _profile_path,
    _ensure_dir,
    _FILE_MODE,
    _DIR_MODE,
)
from stonekeep.exceptions import StonekeepError, ProfileNotFoundError


class TestResolveProfile:
    def test_explicit_profile(self):
        assert _resolve_profile("myprofile") == "myprofile"

    def test_env_var(self, monkeypatch):
        monkeypatch.setenv("STONEKEEP_PROFILE", "envprofile")
        assert _resolve_profile("") == "envprofile"

    def test_explicit_overrides_env(self, monkeypatch):
        monkeypatch.setenv("STONEKEEP_PROFILE", "envprofile")
        assert _resolve_profile("explicit") == "explicit"

    def test_no_profile_raises(self, monkeypatch):
        monkeypatch.delenv("STONEKEEP_PROFILE", raising=False)
        with pytest.raises(StonekeepError, match="No profile specified"):
            _resolve_profile("")


class TestProfileNameValidation:
    """Verify that path-traversal and other unsafe names are rejected."""

    @pytest.mark.parametrize("name", [
        "myprofile",
        "my-profile",
        "my_profile",
        "my.profile",
        "Profile123",
        "0leading-digit",
    ])
    def test_valid_names_accepted(self, name):
        _validate_profile_name(name)  # should not raise

    @pytest.mark.parametrize("name,reason", [
        ("..", "dot-dot traversal"),
        ("../etc/passwd", "relative path escape"),
        (".hidden", "leading dot (hidden file)"),
        ("foo/bar", "slash in name"),
        ("foo\\bar", "backslash in name"),
        ("", "empty string"),
        ("-leadingdash", "leading dash"),
        ("_leadingunderscore", "leading underscore"),
        ("name with spaces", "spaces"),
        ("name\x00null", "null byte"),
    ])
    def test_invalid_names_rejected(self, name, reason):
        with pytest.raises(StonekeepError, match="Invalid profile name"):
            _validate_profile_name(name)

    def test_profile_path_rejects_bad_name(self, tmp_path, monkeypatch):
        monkeypatch.setenv("STONEKEEP_DEV_DIR", str(tmp_path))
        with pytest.raises(StonekeepError):
            _profile_path("../../etc/passwd")


class TestDirectoryPermissions:
    def test_ensure_dir_creates_with_0700(self, tmp_path):
        target = tmp_path / "newdir"
        _ensure_dir(target)
        assert target.is_dir()
        actual = target.stat().st_mode & 0o777
        assert actual == _DIR_MODE

    def test_ensure_dir_fixes_loose_permissions(self, tmp_path):
        target = tmp_path / "loosedir"
        target.mkdir(mode=0o755)
        _ensure_dir(target)
        actual = target.stat().st_mode & 0o777
        assert actual == _DIR_MODE


class TestFilePermissions:
    @pytest.fixture
    def dev_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("STONEKEEP_DEV_DIR", str(tmp_path))
        return tmp_path

    def test_save_creates_file_with_0600(self, dev_dir):
        vault = WritableVault(profile="test")
        vault.set_config({"key": "val"})
        path = dev_dir / "test.json"
        actual = path.stat().st_mode & 0o777
        assert actual == _FILE_MODE

    def test_save_preserves_0600_on_overwrite(self, dev_dir):
        vault = WritableVault(profile="test")
        vault.set_config({"key": "val1"})
        vault.set_config({"key": "val2"})
        path = dev_dir / "test.json"
        actual = path.stat().st_mode & 0o777
        assert actual == _FILE_MODE

    def test_directory_created_with_0700_on_save(self, tmp_path, monkeypatch):
        subdir = tmp_path / "nested" / "profiles"
        monkeypatch.setenv("STONEKEEP_DEV_DIR", str(subdir))
        vault = WritableVault(profile="test")
        vault.set_config({"key": "val"})
        actual = subdir.stat().st_mode & 0o777
        assert actual == _DIR_MODE


class TestAtomicWrite:
    @pytest.fixture
    def dev_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("STONEKEEP_DEV_DIR", str(tmp_path))
        return tmp_path

    def test_no_temp_files_left_on_success(self, dev_dir):
        vault = WritableVault(profile="test")
        vault.set_config({"key": "val"})
        files = list(dev_dir.iterdir())
        assert len(files) == 1
        assert files[0].name == "test.json"

    def test_data_integrity_after_write(self, dev_dir):
        vault = WritableVault(profile="test")
        vault.set_config({"key1": "val1", "key2": "val2"})
        data = json.loads((dev_dir / "test.json").read_text())
        assert data == {"key1": "val1", "key2": "val2"}

    def test_overwrite_is_atomic(self, dev_dir):
        """Verify overwrite replaces content completely."""
        vault = WritableVault(profile="test")
        vault.set_config({"old": "data"})
        vault.set_config({"new": "data"})
        data = json.loads((dev_dir / "test.json").read_text())
        assert data == {"new": "data"}
        assert "old" not in data


class TestDevVault:
    @pytest.fixture
    def dev_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("STONEKEEP_DEV_DIR", str(tmp_path))
        return tmp_path

    def _write_profile(self, dev_dir, name, data):
        path = dev_dir / f"{name}.json"
        path.write_text(json.dumps(data))

    def test_get_config(self, dev_dir):
        self._write_profile(dev_dir, "test", {"key1": "val1", "key2": "val2"})
        vault = Vault(profile="test")
        config = vault.get_config()
        assert config == {"key1": "val1", "key2": "val2"}

    def test_get_secret(self, dev_dir):
        self._write_profile(dev_dir, "test", {"api_key": "secret123"})
        vault = Vault(profile="test")
        assert vault.get_secret("api_key") == "secret123"

    def test_get_secret_missing_key(self, dev_dir):
        self._write_profile(dev_dir, "test", {"key1": "val1"})
        vault = Vault(profile="test")
        with pytest.raises(StonekeepError, match="not found"):
            vault.get_secret("missing")

    def test_profile_not_found(self, dev_dir):
        vault = Vault(profile="nonexistent")
        with pytest.raises(ProfileNotFoundError):
            vault.get_config()

    def test_ping_always_true(self, dev_dir):
        vault = Vault(profile="test")
        assert vault.ping() is True

    def test_url_and_ca_cert_accepted(self, dev_dir):
        """url and ca_cert params should be accepted but ignored."""
        self._write_profile(dev_dir, "test", {"key": "val"})
        vault = Vault(profile="test", url="tls://host:9700", ca_cert="/path/to/cert")
        assert vault.get_config() == {"key": "val"}


class TestDevWritableVault:
    @pytest.fixture
    def dev_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("STONEKEEP_DEV_DIR", str(tmp_path))
        return tmp_path

    def _write_profile(self, dev_dir, name, data):
        path = dev_dir / f"{name}.json"
        path.write_text(json.dumps(data))

    def test_set_config(self, dev_dir):
        self._write_profile(dev_dir, "test", {"old": "data"})
        vault = WritableVault(profile="test")
        vault.set_config({"new": "data"})
        result = Vault(profile="test").get_config()
        assert result == {"new": "data"}

    def test_set_secret(self, dev_dir):
        self._write_profile(dev_dir, "test", {"existing": "val"})
        vault = WritableVault(profile="test")
        vault.set_secret("new_key", "new_val")
        result = Vault(profile="test").get_config()
        assert result == {"existing": "val", "new_key": "new_val"}

    def test_delete_secret(self, dev_dir):
        self._write_profile(dev_dir, "test", {"keep": "yes", "remove": "this"})
        vault = WritableVault(profile="test")
        vault.delete_secret("remove")
        result = Vault(profile="test").get_config()
        assert result == {"keep": "yes"}

    def test_delete_nonexistent_key(self, dev_dir):
        self._write_profile(dev_dir, "test", {"keep": "yes"})
        vault = WritableVault(profile="test")
        vault.delete_secret("nonexistent")  # Should not raise
        result = Vault(profile="test").get_config()
        assert result == {"keep": "yes"}


class TestDevModeWarning:
    def test_import_emits_warning(self):
        """Dev backend should emit a warning when imported."""
        import importlib
        import stonekeep._devbackend as mod
        with pytest.warns(UserWarning, match="DEV mode"):
            importlib.reload(mod)
