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

This package is production-only and talks to the Stonekeep Guardian service.
