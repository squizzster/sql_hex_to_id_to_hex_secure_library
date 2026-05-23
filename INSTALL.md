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

For deployed public IDs, replace `DOMAIN_SALT_HEX` near the top of
`sql_id_library.py` with a deployment-specific random hex value. It must contain
`64..512` hex characters and is decoded to `32..256` bytes:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

The bundled salt is public and is rejected during normal library use. Replace it
before deployment. The demo and tests set `XCTX_DEMO_ALLOW_BUNDLED_DOMAIN_SALT=1`
so sample IDs can still be generated with the bundled salt. Do not set that
environment variable for deployed application processes.

Treat the salt as one of three independent key inputs, alongside
`XCTX_ID_PASSWORD` and the pepper file.

Do not reuse the salt as `XCTX_ID_PASSWORD` or the pepper. Generate all values
independently.

## 2. Set The Runtime Secret

Set `XCTX_ID_PASSWORD` to a separate strong hex secret. It must contain
`64..512` hex characters and is decoded to `32..256` secret bytes before key
derivation:

```bash
export XCTX_ID_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

Store this in your normal secret manager or process environment. Do not commit
it to source control.

## 3. Create The Pepper File

The default pepper path is:

```text
~/.sql_hex_id_pepper_file.key
```

Create it with `64..512` hex characters. The raw pepper file is capped at 512
bytes, so a max-length pepper must not include a trailing newline. The minimum
generator is:

```bash
python -c "import secrets; print(secrets.token_hex(32))" > ~/.sql_hex_id_pepper_file.key
chmod 0400 ~/.sql_hex_id_pepper_file.key
```

The application process must be able to read this file. On POSIX systems the
library rejects pepper files that allow execution, group write, or any
other-user access. `0400`, `0600`, `0440`, and `0640` are acceptable patterns.

Changing `DOMAIN_SALT_HEX`, `XCTX_ID_PASSWORD`, or the pepper after public IDs
have been issued makes those existing public IDs stop decoding.

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
python run_tests_for_sql_id.py
```

Run the developer demo:

```bash
./bin_demo/sql_id_demo_for_dev.py --int_id 1 --details
```

If the demo prints a bundled-salt warning to stderr, the deployment salt has not
been changed yet. Normal library use rejects that bundled salt unless
`XCTX_DEMO_ALLOW_BUNDLED_DOMAIN_SALT=1` is set for demo/test use.
