# SQL BIGINTs inside. Public hex outside.

`sql_id_library` keeps your database on compact BIGINT primary keys while the
outside world sees deterministic, secret-keyed, reversible public handles.

```python
from sql_id_library import hex_to_id, id_to_hex

public_id = id_to_hex(order.id)
order_id = hex_to_id(public_id)
```

The public ID is always:

```text
32 lowercase hex characters
```

No UUID primary keys.
No public-ID lookup table.
No exposed sequential IDs.

For deployment setup, including the public-ID salt, runtime secret, and pepper
file, see [INSTALL.md](INSTALL.md).

---

## Deployment Hardening

For deployed public IDs, use three independent inputs:

- `DOMAIN_SALT_HEX` near the top of `sql_id_library.py`
- `XCTX_ID_PASSWORD` in the process environment
- a disk pepper file, defaulting to `~/.sql_hex_id_pepper_file.key`

Generate each one independently. `DOMAIN_SALT_HEX`, `XCTX_ID_PASSWORD`, and the
pepper must each be `64..512` hex characters. The library decodes each value to
`32..256` bytes, rejects low byte diversity and extreme bit imbalance, then
normalizes the accepted bytes to a role-separated SHA-512 digest before key
derivation. This normalization gives every allowed input length the same
internal size; it does not add entropy to weak input.

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Recommended pepper setup:

```bash
python -c "import secrets; print(secrets.token_hex(32))" > ~/.sql_hex_id_pepper_file.key
chmod 0400 ~/.sql_hex_id_pepper_file.key
```

The bundled salt is public and is rejected during normal library use. Replace it
before deployment. The demo and tests set `XCTX_DEMO_ALLOW_BUNDLED_DOMAIN_SALT=1`
so sample IDs can still be generated with the bundled salt. Do not set that
environment variable for deployed application processes.

Changing the salt, runtime secret, or pepper after public IDs have been issued makes
those existing public IDs stop decoding.

---

## Bit Layout

The current format uses the full 128-bit / 32-hex-character budget:

```text
3 version bits + 5 label bits + 1 range bit + id bits + keyed tag bits = 128 bits
```

Plain value before the keyed permutation:

```text
[ version ][ label ][ canonical range ][ SQL id ][ keyed validation tag ]
```

Then the whole 128-bit value is passed through a secret-keyed Feistel
permutation and encoded as lowercase hex.

Capacity:

| Field   | Values |
| ------- | ------ |
| Version | `0..7`; issues `2`; `1`, `3..6` inactive/future; `0`, `7` reserved |
| Label   | `0` means no label, `1..30` named, `31` reserved |
| Range   | `0` for IDs `1..4,294,967,295`; `1` for IDs `4,294,967,296..18,446,744,073,709,551,615` |
| SQL ID  | BIGINT UNSIGNED range `1..18,446,744,073,709,551,615` |
| Tag     | 87 keyed validation bits in range `0`; 55 keyed validation bits in range `1` |

Every positive BIGINT UNSIGNED value has exactly one canonical encoding.
Values that fit inside 32 bits use the spare envelope space as a larger tag.

---

## Unlabeled API

Use this when the public ID does not need a table/type/bucket label:

```python
from sql_id_library import id_to_hex, hex_to_id

public_hex = id_to_hex(123)
id_value = hex_to_id(public_hex)
```

`hex_to_id()` only accepts public IDs with:

```text
label = 0
```

If you pass a labeled public ID to `hex_to_id()`, it returns `None`.

---

## Labeled API

Use labels when the public ID should carry a numeric table/type/bucket label:

```python
from sql_id_library import (
    configure_sql_id,
    hex_to_id_label,
    id_to_hex_label,
)

configure_sql_id({
    "labels": {
        "users": 1,
        "plans": 2,
        "repair": 3,
    },
})

public_hex = id_to_hex_label(123, "users")
user_id = hex_to_id_label(public_hex, "users")
```

You can configure all labels at once in code:

```python
configure_sql_id({
    "labels": {
        "dry_run": 1,
        "plan": 2,
        "execute": 3,
        "enquire": 4,
        "repair": 5,
    },
})
```

You can also configure only the pepper path, or both values together:

```python
configure_sql_id({
    "pepper_file_location": "/etc/myapp/sql_hex_id_pepper.key",
})

configure_sql_id({
    "pepper_file_location": "/etc/myapp/sql_hex_id_pepper.key",
    "labels": {
        "users": 1,
        "plans": 2,
    },
})
```

Or load SQL ID config from a file:

```python
from sql_id_library import load_sql_id_config_from_file

load_sql_id_config_from_file("./conf/test_sql_id_config.json")
load_sql_id_config_from_file("./conf/test_sql_id_config.yaml")
```

JSON support uses the Python standard library. YAML support is optional and
requires PyYAML; if it is unavailable, loading a YAML file raises `ValueError`.
If same-stem files exist in more than one supported format, for example
`conf/test_sql_id_config.json` and `conf/test_sql_id_config.yaml`, the loader
reads every available same-stem `.json`, `.yaml`, and `.yml` file and refuses to
continue unless they normalize to exactly the same SQL ID config. Each config
file must be `2000` bytes or smaller. Duplicate file keys, duplicate normalized
label names, duplicate label IDs, boolean label IDs, and YAML boolean keys are
rejected.

File-loaded config is cached automatically after the first successful load.
Later calls to `load_sql_id_config_from_file()` for the same same-stem path
reuse the cached config and do not re-read disk. Encoding and decoding use the
in-memory config only. If application logic intentionally needs to re-read
config files from disk, call:

```python
from sql_id_library import reload_sql_id_config_from_file

reload_sql_id_config_from_file("./conf/test_sql_id_config.yaml")
```

The pepper file is opened without following symlinks on POSIX systems, then
validated and read through that same file descriptor. It is cached after first
successful validation for the configured path. If application logic
intentionally rotates or rewrites the pepper file while the process is running,
call:

```python
from sql_id_library import reload_sql_id_pepper

reload_sql_id_pepper()
```

Supported file shapes:

```yaml
pepper_file_location: ~/.sql_hex_id_pepper_file.key
labels:
  1: dry_run
  2: plan
  3: execute
  4: enquire
  5: repair
```

```json
{
  "pepper_file_location": "~/.sql_hex_id_pepper_file.key",
  "labels": {
    "dry_run": 1,
    "plan": 2,
    "execute": 3,
    "enquire": 4,
    "repair": 5
  }
}
```

Strict behavior:

```python
plain = id_to_hex(123)
user = id_to_hex_label(123, "users")

hex_to_id(plain)                  # 123
hex_to_id(user)                   # None

hex_to_id_label(user, "users")    # 123
hex_to_id_label(user, "repair")   # None
hex_to_id_label(plain, "users")   # None
```

You may also pass numeric label IDs directly:

```python
id_to_hex_label(123, 1)
hex_to_id_label(public_hex, 1)
```

Allowed label IDs for the labeled API are `1..30`. Label `0` is reserved for
the unlabeled API.
Label `31` is reserved for future escape behavior.

---

## Validation

For normal application flow, use the strict integer-returning APIs:

```python
id_value = hex_to_id(public_hex)
user_id = hex_to_id_label(public_hex, "users")
```

For diagnostics:

```python
result = validate_hex(public_hex)          # expects label 0
result = validate_hex_label(public_hex, "users")
result = inspect_hex(public_hex)           # accepts any non-reserved label
```

`inspect_hex()` and `hex_to_parts()` are inspection helpers. Do not use them as
typed route enforcement. Enforcement should always name the expected label.

Validation result fields include:

```text
ok
id
public_hex
label_id
label
range_class
tag_bits
version
error_code
error
```

`hex_to_parts(public_hex)` returns:

```text
(label_id, label_name, range_class, tag_bits, version, integer_id)
```

Typical errors include:

| Code                  | Meaning                                 |
| --------------------- | --------------------------------------- |
| `not_string`          | Input was not a string                  |
| `invalid_hex`         | Input contained non-hex characters      |
| `unsupported_length`  | Public ID was not exactly 32 hex chars  |
| `bad_config`          | Runtime secret, salt, or layout config failed |
| `missing_pepper_file` | Pepper file does not exist              |
| `unreadable_pepper_file` | Pepper file could not be read        |
| `bad_pepper_permissions` | Pepper file permissions are unsafe   |
| `pepper_too_short`    | Pepper hex is shorter than 64 chars     |
| `pepper_too_long`     | Pepper file or hex is longer than 512 chars |
| `invalid_pepper_hex`  | Pepper file did not contain valid hex   |
| `low_diversity_pepper` | Pepper bytes had too little diversity  |
| `low_bit_balance_pepper` | Pepper bits were implausibly imbalanced |
| `tag_mismatch`        | Keyed validation tag did not match      |
| `unsupported_version` | Decoded version is not active           |
| `reserved_label`      | Decoded label is reserved               |
| `label_mismatch`      | Decoded label was not the expected one  |
| `id_out_of_range`     | Decoded ID is outside its canonical range |

---

## Configuration

Set all three key inputs before issuing IDs:

1. `DOMAIN_SALT_HEX` in source/config.
2. `XCTX_ID_PASSWORD` in the environment.
3. A readable pepper file at the configured `pepper_file_location`.

Use `64..512` hex characters for `XCTX_ID_PASSWORD`. The minimum is exactly
what the command below prints: `64` hex characters, decoded to `32` bytes.
Accepted values are normalized to 64 internal bytes with SHA-512 before key
derivation.

```bash
export XCTX_ID_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

Use `64..512` hex characters for the pepper. The raw pepper file is capped at
512 bytes, so a max-length pepper must not include a trailing newline. The same
hex, byte-diversity, bit-balance, and SHA-512 normalization rules apply to
`DOMAIN_SALT_HEX`, `XCTX_ID_PASSWORD`, and the pepper:

```bash
python -c "import secrets; print(secrets.token_hex(32))" > ~/.sql_hex_id_pepper_file.key
chmod 0400 ~/.sql_hex_id_pepper_file.key
```

Keep it private.
Keep it stable.
Rotate deliberately; changing the salt, runtime secret, or pepper makes previously
issued public IDs stop decoding. Do not reuse one value for another.

---

## Security Shape

For one fixed expected label, including `label=0`, a random 32-character hex
string is accepted with probability:

```text
(2^64 - 1) / 2^128
```

That is just under:

```text
1 in 2^64
```

That overall probability is across the full BIGINT ID space. For a specific
small-range ID such as `1`, the keyed tag check uses `87` tag bits; the
large-range path uses `55` tag bits.

The strict APIs enforce one expected label:

```python
hex_to_id(public_hex)                 # expected label 0
hex_to_id_label(public_hex, "users")  # expected label users
```

Generic inspection accepts labels `0..30`, so it has a wider acceptance surface.
Use it for diagnostics, not authorization-sensitive routing.

The public ID is not a permission token.

It is not a session token.

It is not a bearer credential.

It is a public reference to a row. Decode it, load the row, and perform normal
authorization and business-rule checks.

---

## Bad IDs Should Count

A bad public ID might be a typo, stale link, broken client, bot, or guessing.
Treat repeated bad IDs as suspicious.

Count them by whatever makes sense for your system:

```text
IP address
session
authenticated user
API key
tenant
route
device
time bucket
```

A simple rate limit changes the economics completely:

```text
10 bad IDs per 30 minutes per bucket
```

is:

```text
175,200 guesses per year per bucket
```

At that rate, the expected time to hit any strict expected-label decoder-valid
handle is roughly:

```text
105,289,635,123,913 years per bucket
```

That still only means decoder-valid.

It does not mean real row.

It does not mean authorized.

It does not mean access granted.

---

## Developer Demo

```bash
./bin_demo/sql_id_demo_for_dev.py
./bin_demo/sql_id_demo_for_dev.py --int_id 1
./bin_demo/sql_id_demo_for_dev.py --int_id 1 --label repair
./bin_demo/sql_id_demo_for_dev.py --config-file ./conf/test_sql_id_config.yaml --int_id 1 --label repair
./bin_demo/sql_id_demo_for_dev.py --hex_id "<public_hex>"
./bin_demo/sql_id_demo_for_dev.py --hex_id "<public_hex>" --label repair
```

The demo loads local sample labels from `./conf/test_sql_id_config.yaml`:

```text
dry_run=1
plan=2
execute=3
enquire=4
repair=5
```

Applications should configure their own pepper path and label registry at startup.
