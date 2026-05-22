# Install And Deployment Setup

## 0. Install The Package

From this repository:

```bash
pip install .
```

If you want to load YAML label files:

```bash
pip install ".[yaml]"
```

## 1. Set A Deployment Salt

For deployed public IDs, replace `DOMAIN_SALT_HEX` near the top of
`sql_id_library.py` with a deployment-specific 32-byte random hex value:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

The bundled salt is public and is accepted by the library, but changing it is
strongly recommended for public-ID deployment hardening. If an attacker does not
have the deployment salt, they need both the deployed source/config value and
`XCTX_ID_PASSWORD` to reproduce the public-ID scheme.

Do not reuse the salt as `XCTX_ID_PASSWORD`. Generate both values independently.

## 2. Set The Runtime Secret

Set `XCTX_ID_PASSWORD` to a separate strong secret of at least 32 UTF-8 bytes:

```bash
export XCTX_ID_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

Store this in your normal secret manager or process environment. Do not commit
it to source control.

Changing either `DOMAIN_SALT_HEX` or `XCTX_ID_PASSWORD` after public IDs have
been issued makes those existing public IDs stop decoding.

## 3. Configure Labels

Configure labels in application code:

```python
configure_sql_id_labels({
    "dry_run": 1,
    "plan": 2,
    "execute": 3,
    "enquire": 4,
    "repair": 5,
})
```

Or load labels from `./conf/test_sql_id_labels.json` or
`./conf/test_sql_id_labels.yaml`. YAML support is optional and requires the
`yaml` extra shown above:

```bash
pip install ".[yaml]"
```

## 4. Verify

Run the regression tests:

```bash
python run_tests_for_sql_id.py
```

Run the developer demo:

```bash
./bin_demo/sql_id_demo_for_dev.py --int_id 1 --details
```

If the demo prints a bundled-salt warning to stderr, the deployment salt has not
been changed yet.
