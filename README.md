# stonekeep

Python client for Stonekeep profile-based config and secret access.

## Install

```bash
pip install "stonekeep @ git+https://github.com/Stonefish-Labs/stonekeep.git"
```

## Quick start

```python
from stonekeep import Vault

vault = Vault(profile="my-profile")
config = vault.get_config()
token = vault.get_secret("api_token")
```

## Modes

- Default (`STONEKEEP_MODE` unset): uses the Stonekeep Guardian service.
- Dev mode (`STONEKEEP_MODE=dev`): stores profile data in local JSON files for local testing.

