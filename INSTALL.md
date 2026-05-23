# Install And Deployment Setup

## 0. Install The Package

From this repository:

```bash
pip install .
```

If you want to load YAML config files:

```bash
pip install ".[yaml]"
```

## 1. Set A Deployment Salt

For deployed public IDs, set `SQL_ID_LIBRARY_DOMAIN_SALT_HEX` in the process
environment. It must contain `64..512` hex characters. The decoded `32..256`
bytes are sanity-checked and then normalized to a role-separated SHA-512 digest
before key derivation:

```bash
export SQL_ID_LIBRARY_DOMAIN_SALT_HEX="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

`SQL_ID_LIBRARY_DOMAIN_SALT_HEX` is required for normal library use. The library
does not contain a deployment salt fallback.

Treat the salt as one of three independent key inputs, alongside
`SQL_ID_LIBRARY_PASSWORD_HEX` and the pepper file.

Do not reuse the salt as `SQL_ID_LIBRARY_PASSWORD_HEX` or the pepper. Generate all values
independently.

## 2. Set The Runtime Secret

Set `SQL_ID_LIBRARY_PASSWORD_HEX` to a separate strong hex secret. It must contain
`64..512` hex characters. The decoded `32..256` secret bytes are checked with
the same rules as the salt and pepper, then normalized to a role-separated
SHA-512 digest before key derivation:

```bash
export SQL_ID_LIBRARY_PASSWORD_HEX="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

Store this in your normal secret manager or process environment. Do not commit
it to source control.

## 3. Create The Pepper File

The default pepper path is:

```text
~/.sql_hex_id_pepper_file.key
```

Create it with `64..512` hex characters. One final line ending from shell
redirection is accepted; other leading or trailing whitespace is rejected. The
raw pepper file is capped at 512 bytes, so a max-length pepper must not include
a trailing newline. The decoded pepper bytes use the same byte-diversity,
bit-balance, and SHA-512 normalization rules as the salt and runtime secret.
The minimum generator is:

```bash
python -c "import secrets; print(secrets.token_hex(32))" > ~/.sql_hex_id_pepper_file.key
chmod 0400 ~/.sql_hex_id_pepper_file.key
```

The application process must be able to read this file. On POSIX systems the
library rejects pepper files that allow execution, group write, or any
other-user access. `0400`, `0600`, `0440`, and `0640` are acceptable patterns.
The library intentionally does not enforce a specific owner, group, parent
directory owner, or broader filesystem policy. Those are deployment decisions:
set them in your application, container, service manager, or secrets-management
layer according to the user and environment that actually run the process.

Changing `SQL_ID_LIBRARY_DOMAIN_SALT_HEX`, `SQL_ID_LIBRARY_PASSWORD_HEX`, or the
pepper after public IDs have been issued makes those existing public IDs stop
decoding.

## 4. Configure SQL ID Settings

Configure labels and/or a custom pepper path in application code:

```python
configure_sql_id({
    "pepper_file_location": "~/.sql_hex_id_pepper_file.key",
    "labels": {
        "dry_run": 1,
        "plan": 2,
        "execute": 3,
        "enquire": 4,
        "repair": 5,
    },
})
```

Or load config from `./conf/test_sql_id_config.json` or
`./conf/test_sql_id_config.yaml`. YAML support is optional and requires the
`yaml` extra shown above:

```bash
pip install ".[yaml]"
```

```python
load_sql_id_config_from_file("./conf/test_sql_id_config.yaml")
```

## 5. Verify

Run the regression tests:

```bash
python -m pytest
```

`python run_tests_for_sql_id.py` remains as a compatibility wrapper.

Run the developer demo:

```bash
./bin_demo/sql_id_demo_for_dev.py --int_id 1 --details
```

If real environment values are missing, the demo prints the demo-only values it
uses so the sample output can be reproduced. Real applications should set their
own stable environment values and pepper file.
