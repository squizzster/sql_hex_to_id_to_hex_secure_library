# SQL integers inside. Public hex outside.

`sql_id_library` keeps your database on compact integer primary keys while the
outside world sees deterministic, secret-keyed, reversible public handles.

```python
from sql_id_library import hex_to_id, id_to_hex

public_id = id_to_hex(order.id)
order_id = hex_to_id(public_id)
```

The public ID is always:

```text
16 lowercase hex characters
```

No UUID primary keys.
No public-ID lookup table.
No exposed sequential IDs.

---

## Bit Layout

The current format uses the full 64-bit / 16-hex-character budget:

```text
3 version bits + 5 label bits + 32 id bits + 24 keyed tag bits = 64 bits
```

Plain value before encryption:

```text
[ version ][ label ][ zero-based SQL id index ][ keyed validation tag ]
```

Then the whole 64-bit value is passed through a secret-keyed Feistel permutation
and encoded as lowercase hex.

Capacity:

| Field   | Values                                      |
| ------- | ------------------------------------------- |
| Version | `0..7`; issues `1`, reserves `0` and `7`    |
| Label   | `0` means no label, `1..30` named, `31` reserved |
| SQL ID  | `1..4,294,967,295`                          |
| Tag     | 24 keyed validation bits                    |

---

## Unlabeled API

Use this when you just want the old simple behavior:

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

Use labels when the public ID should carry a table/type/bucket:

```python
from sql_id_library import (
    configure_sql_id_labels,
    hex_to_id_label,
    id_to_hex_label,
)

configure_sql_id_labels({
    "users": 1,
    "plans": 2,
    "repair": 3,
})

public_hex = id_to_hex_label(123, "users")
user_id = hex_to_id_label(public_hex, "users")
```

You can configure all labels at once in code:

```python
configure_sql_id_labels({
    "dry_run": 1,
    "plan": 2,
    "execute": 3,
    "enquire": 4,
    "repair": 5,
})
```

Or load labels from a file:

```python
from sql_id_library import load_sql_id_labels_from_file

load_sql_id_labels_from_file("./conf/test_sql_id_labels.json")
load_sql_id_labels_from_file("./conf/test_sql_id_labels.yaml")
```

JSON support uses the Python standard library. YAML support is optional and
requires PyYAML; if it is unavailable, loading a YAML file raises `ValueError`.
If same-stem files both exist, for example `conf/test_sql_id_labels.json` and
`conf/test_sql_id_labels.yaml`, the loader reads both and refuses to continue
unless they normalize to exactly the same label registry. Each label file must be
`2000` bytes or smaller. Duplicate file keys, duplicate normalized label names,
duplicate label IDs, and YAML boolean label IDs are rejected.

File-loaded labels are cached after the first successful load, which is the
right default for long-running tasks. If application logic intentionally needs
to re-read label files from disk, call:

```python
from sql_id_library import reload_sql_id_labels_from_file

reload_sql_id_labels_from_file("./conf/test_sql_id_labels.yaml")
```

`re_load_sql_id_labels_from_file()` is also available as a spelling-friendly
alias for explicit application-controlled reloads.

Supported file shapes:

```yaml
1: dry_run
2: plan
3: execute
4: enquire
5: repair
```

```json
{
  "dry_run": 1,
  "plan": 2,
  "execute": 3,
  "enquire": 4,
  "repair": 5
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

Allowed labeled IDs are `1..30`. Label `0` is reserved for the unlabeled API.
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
version
error_code
error
```

Typical errors include:

| Code                  | Meaning                                 |
| --------------------- | --------------------------------------- |
| `not_string`          | Input was not a string                  |
| `invalid_hex`         | Input contained non-hex characters      |
| `unsupported_length`  | Public ID was not exactly 16 hex chars  |
| `bad_config`          | Secret is missing or too weak           |
| `tag_mismatch`        | Keyed validation tag did not match      |
| `unsupported_version` | Decoded version is not active           |
| `reserved_label`      | Decoded label is reserved               |
| `label_mismatch`      | Decoded label was not the expected one  |
| `id_out_of_range`     | Decoded ID is outside the public range  |

---

## Configuration

Set `XCTX_ID_PASSWORD` to a strong secret.

Use at least 32 UTF-8 bytes:

```bash
export XCTX_ID_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

The fixed domain salt in the library is not secret.

The environment value is the secret key.

Keep it private.
Keep it stable.
Rotate it deliberately.

---

## Security Shape

For one fixed expected label, including `label=0`, a random 16-character hex
string is accepted with probability:

```text
(2^32 - 1) / 2^64
```

That is just under:

```text
1 in 2^32
```

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
24,515 years per bucket
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
./bin_demo/sql_id_demo_for_dev.py --int_id 1 --label users
./bin_demo/sql_id_demo_for_dev.py --labels-file ./conf/test_sql_id_labels.yaml --int_id 1 --label repair
./bin_demo/sql_id_demo_for_dev.py --hex_id "<public_hex>"
./bin_demo/sql_id_demo_for_dev.py --hex_id "<public_hex>" --label users
```

The demo configures local sample labels:

```text
users=1
plans=2
repair=3
```

Applications should configure their own label registry at startup.
