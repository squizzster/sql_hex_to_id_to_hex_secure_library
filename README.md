# SQL ID layout-registry library

A small deterministic library for turning positive SQL integer IDs into public hex handles and back again.

The public API is intentionally simple:

```python
from sql_id_library import id_to_hex, hex_to_id, validate_hex

public_hex = id_to_hex(123)                  # default: uint32 normal, 16 hex chars
public_hex = id_to_hex(123, profile="uint16")
public_hex = id_to_hex(123, profile="uint32", boosted=True)

id_value = hex_to_id(public_hex)             # returns int, or None
result = validate_hex(public_hex)            # returns structured success/error detail
```

Aliases are included for the SQL-style names:

```python
from sql_id_library import sql_generate_id, sql_decode_id, sql_validate_id

public_hex = sql_generate_id(123)
id_value = sql_decode_id(public_hex)
result = sql_validate_id(public_hex)
```

`id_to_hex()` and `hex_to_id()` are the convenience functions. They return `None` on invalid input, weak/missing configuration, tampering, or wrong secrets. `validate_hex()` is the diagnostic function. It returns a `SqlIdValidation` object with `ok`, `id`, `profile`, `mode`, `version`, `error_code`, and `error`.

## Configuration

Set `XCTX_ID_PASSWORD` to at least 32 UTF-8 bytes of secret. A direct OS-CSPRNG secret is recommended:

```bash
export XCTX_ID_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

The fixed domain salt in `sql_id_library.py` is not secret. The environment value is the secret key.

## Layout registry

Callers choose from fixed named profiles. They do not provide arbitrary bit counts.

### Normal mode

| Profile  | ID bits | Total bits | Bytes | Hex chars | Tag bits | Layout                       |
| -------- | ------: | ---------: | ----: | --------: | -------: | ---------------------------- |
| `uint8`  |       8 |         40 |     5 |        10 |       28 | `4 version + 8 id + 28 tag`  |
| `uint16` |      16 |         48 |     6 |        12 |       28 | `4 version + 16 id + 28 tag` |
| `uint24` |      24 |         56 |     7 |        14 |       28 | `4 version + 24 id + 28 tag` |
| `uint32` |      32 |         64 |     8 |        16 |       28 | `4 version + 32 id + 28 tag` |
| `uint48` |      48 |         80 |    10 |        20 |       28 | `4 version + 48 id + 28 tag` |
| `uint64` |      64 |         96 |    12 |        24 |       28 | `4 version + 64 id + 28 tag` |

### Boosted mode

| Profile  | ID bits | Total bits | Bytes | Hex chars | Tag bits | Layout                       |
| -------- | ------: | ---------: | ----: | --------: | -------: | ---------------------------- |
| `uint8`  |       8 |         72 |     9 |        18 |       60 | `4 version + 8 id + 60 tag`  |
| `uint16` |      16 |         88 |    11 |        22 |       68 | `4 version + 16 id + 68 tag` |
| `uint24` |      24 |        104 |    13 |        26 |       76 | `4 version + 24 id + 76 tag` |
| `uint32` |      32 |        112 |    14 |        28 |       76 | `4 version + 32 id + 76 tag` |
| `uint48` |      48 |        120 |    15 |        30 |       68 | `4 version + 48 id + 68 tag` |
| `uint64` |      64 |        128 |    16 |        32 |       60 | `4 version + 64 id + 60 tag` |

Decode is length-driven:

| Hex chars | Profile  | Mode      |
| --------: | -------- | --------- |
|        10 | `uint8`  | normal    |
|        12 | `uint16` | normal    |
|        14 | `uint24` | normal    |
|        16 | `uint32` | normal    |
|        20 | `uint48` | normal    |
|        24 | `uint64` | normal    |
|        18 | `uint8`  | boosted   |
|        22 | `uint16` | boosted   |
|        26 | `uint24` | boosted   |
|        28 | `uint32` | boosted   |
|        30 | `uint48` | boosted   |
|        32 | `uint64` | boosted   |

There is no embedded boost flag. The public hex length identifies the decode layout exactly.

## ID ranges

Each profile accepts positive SQL IDs only:

```text
uintN accepts IDs 1..(2^N - 1)
```

Examples:

| Profile  | Maximum accepted SQL ID        |
| -------- | -----------------------------: |
| `uint8`  |                            255 |
| `uint16` |                         65,535 |
| `uint24` |                     16,777,215 |
| `uint32` |                  4,294,967,295 |
| `uint48` |            281,474,976,710,655 |
| `uint64` | 18,446,744,073,709,551,615 |

Internally the SQL ID is stored as a zero-based index: `id_index = sql_id - 1`. The all-ones raw index state is rejected, so `uint32` remains the familiar unsigned-INT maximum rather than accepting `4,294,967,296`.

## Validation result

```python
result = validate_hex("not-a-real-id")

if result.ok:
    print(result.id, result.profile, result.mode)
else:
    print(result.error_code, result.error)
```

Typical error codes:

| Code                  | Meaning                                      |
| --------------------- | -------------------------------------------- |
| `not_string`          | Input is not a string                        |
| `invalid_hex`         | Input contains non-hex characters            |
| `unsupported_length`  | Hex length is not in the layout registry     |
| `bad_config`          | `XCTX_ID_PASSWORD` is missing or too weak    |
| `unsupported_version` | Decoded version is not active                |
| `id_out_of_range`     | Decoded ID index is outside the profile      |
| `tag_mismatch`        | Keyed validation tag does not match          |
| `internal_error`      | Unexpected internal validation failure       |

Generation always returns lowercase hex. Decoding accepts uppercase or lowercase hex.

## Security maths

For a fixed layout, the number of syntactically valid public IDs is:

```text
2^id_bits - 1
```

The public hex space has:

```text
2^total_bits
```

So a uniformly random string of the correct length has probability:

```text
(2^id_bits - 1) / 2^total_bits
```

Normal mode keeps a 28-bit keyed tag and a 4-bit active version check. Therefore every normal profile is just under:

```text
2^-(28 + 4) = 2^-32
```

Boosted mode has at least a 60-bit keyed tag. With the 4-bit active version check, every boosted profile is at least just under:

```text
2^-(60 + 4) = 2^-64
```

Some boosted profiles are stronger:

| Profile  | Boosted tag bits | Approx random-valid probability |
| -------- | ---------------: | ------------------------------- |
| `uint8`  |               60 | `< 2^-64`                       |
| `uint16` |               68 | `< 2^-72`                       |
| `uint24` |               76 | `< 2^-80`                       |
| `uint32` |               76 | `< 2^-80`                       |
| `uint48` |               68 | `< 2^-72`                       |
| `uint64` |               60 | `< 2^-64`                       |

A rate limit of 10 bad IDs per 30 minutes per bucket caps online guessing to:

```text
10 * 2 * 24 * 365 = 175,200 guesses/year/bucket
```

Normal-mode worst-case expected time to hit any valid public ID is roughly:

```text
2^32 / 175,200 ~= 24,515 years/bucket
```

The least-rejecting boosted profile is roughly:

```text
2^64 / 175,200 ~= 105,289,635,123,913 years/bucket
```

This does not make the ID a bearer token. It is a compact public handle for an internal SQL row. Always perform normal authorization checks after decoding.

## Tests

Run:

```bash
python test_sql_id.py
```

The tests cover:

- every normal and boosted profile
- decode-by-length mapping
- boundary IDs
- bad input and bad configuration
- tampering
- wrong password behavior
- inactive versions
- the unused all-ones ID-index state
- Feistel inverse checks
- collision smoke tests
- security maths
