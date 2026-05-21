Absolutely. Here’s the rewritten version as **one coherent website page**, with the SQL argument as the spine and versioning baked into the model instead of bolted on.

---

# SQL integers inside. Public hex outside.

Relational databases are very good at integer primary keys.

They are small.
They are fast.
They index well.
They join well.
They store cheaply in foreign keys.

But raw integer IDs are not always what you want to expose to the world.

Customers, agents, APIs, webhooks, audit trails, logs, support tools, and external systems often need a public identifier: something compact, stable, copyable, and safe to pass around.

`sql_id_library` gives you both.

```python
public_id = id_to_hex(order.id)
order_id = hex_to_id(public_id)
```

Your database keeps the integer.
The outside world gets the hex.

No UUID primary keys.
No public-ID lookup table.
No exposed sequential IDs.

Just a fast SQL key with a clean public handle.

---

## The problem with public IDs as primary keys

UUIDs and long random hex strings are convenient public identifiers.

That is why people use them.

They look good in URLs.
They are easy to hand to other systems.
They avoid obvious sequential IDs.
They work well in distributed environments.

But once you make them your SQL primary key, they become part of every index, every join, and every foreign key that depends on them.

That has a cost.

A string key is wider than an integer key.
It takes more space to index.
It takes more space to repeat in child tables.
It is less cache-friendly.
It can make inserts, joins, and lookups more expensive than they need to be.

Sometimes that trade-off is worth it.

Often it is just habit.

If your database can use an integer primary key, let it.

Then expose something better at the boundary.

---

## The model

Inside SQL:

```text
123
```

Outside SQL:

```text
8f32c4a91b7e05d2
```

The public handle is deterministic, secret-keyed, versioned, tamper-resistant, and reversible by your application.

When a handle comes back in:

```python
sql_id = hex_to_id(public_id)
```

Then your application does the normal database thing:

```text
decode public handle
load row by integer primary key
check authorization
perform the action
```

The public ID is not a permission token.

It is not a session token.

It is not a bearer credential.

It is a public reference to a row.

A better one.

---

# Usage

```python
from sql_id_library import id_to_hex, hex_to_id, validate_hex

public_hex = id_to_hex(123)
id_value = hex_to_id(public_hex)
result = validate_hex(public_hex)
```

By default, `id_to_hex()` uses the `uint32` normal profile.

That gives you:

```text
SQL IDs:   1 to 4,294,967,295
Handle:    16 lowercase hex characters
Mode:      normal
```

For many systems, that is the right default.

Large enough to be useful.
Short enough to be pleasant.
Simple enough to forget about.

---

## Profiles

Profiles define how many SQL IDs can be represented and how long the public handle will be.

| Profile  |                 Max SQL ID | Normal handle | Boosted handle |
| -------- | -------------------------: | ------------: | -------------: |
| `uint8`  |                        255 |  10 hex chars |   18 hex chars |
| `uint16` |                     65,535 |  12 hex chars |   22 hex chars |
| `uint24` |                 16,777,215 |  14 hex chars |   26 hex chars |
| `uint32` |              4,294,967,295 |  16 hex chars |   28 hex chars |
| `uint48` |        281,474,976,710,655 |  20 hex chars |   30 hex chars |
| `uint64` | 18,446,744,073,709,551,615 |  24 hex chars |   32 hex chars |

Use a larger profile when the table or allocation strategy needs it:

```python
id_to_hex(123, profile="uint48")
id_to_hex(123, profile="uint64")
```

Use boosted mode when the public endpoint is highly exposed, hard to rate-limit, or simply deserves stronger rejection of random garbage:

```python
id_to_hex(123, profile="uint32", boosted=True)
```

---

## What is inside the handle?

A public handle contains three things:

```text
scheme version + encoded SQL ID + keyed validation tag
```

The version lets the format evolve.

The encoded ID lets your application recover the SQL integer.

The keyed tag lets the decoder reject tampered, random, malformed, or wrong-secret handles.

The caller does not need to know any of this.

The caller just sees hex.

---

## Versioning

Every generated handle carries a 4-bit scheme version.

The current library issues version `1`.

The version is checked during decode. If the handle belongs to a version that is not active, validation fails cleanly.

```text
unsupported_version
```

This matters because public IDs live for a long time.

They appear in logs, emails, exports, audit trails, integrations, bookmarks, and customer systems. A public ID format should not paint the system into a corner.

Versioning gives the scheme room to change deliberately later.

A future version could change the internal mixing, validation tag, layout policy, or key schedule without making old and new handles ambiguous.

Decode remains simple:

```text
read hex length
select exact layout
decrypt payload
check version
check ID range
check keyed tag
return SQL ID
```

There is no “try every format”.

There is no guessing.

The handle length identifies the profile and mode.
The embedded version identifies the scheme.

---

## Decode is length-driven

There is no separate boosted flag inside the public API.

A handle’s length selects the layout.

For example:

```text
16 hex chars  -> uint32 normal
28 hex chars  -> uint32 boosted
24 hex chars  -> uint64 normal
32 hex chars  -> uint64 boosted
```

That keeps the public format compact and unambiguous.

---

# Validation

For normal application flow, use:

```python
id_value = hex_to_id(public_hex)
```

It returns the SQL ID or `None`.

For diagnostics, use:

```python
result = validate_hex(public_hex)
```

The result includes:

```text
ok
id
profile
mode
version
error_code
error
```

Typical errors include:

| Code                  | Meaning                            |
| --------------------- | ---------------------------------- |
| `not_string`          | Input was not a string             |
| `invalid_hex`         | Input contained non-hex characters |
| `unsupported_length`  | No layout exists for this length   |
| `bad_config`          | Secret is missing or too weak      |
| `unsupported_version` | Decoded version is not active      |
| `id_out_of_range`     | Decoded ID is outside the profile  |
| `tag_mismatch`        | Keyed validation tag did not match |

The convenience API is quiet.

The validation API explains.

---

# Configuration

Set `XCTX_ID_PASSWORD` to a strong secret.

Use at least 32 UTF-8 bytes.

```bash
export XCTX_ID_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

The fixed domain salt in the library is not secret.

The environment value is the secret key.

Keep it private.
Keep it stable.
Rotate it deliberately.

---

# Security shape

For one fixed profile, mode, version, and secret, every accepted SQL ID has exactly one public handle.

A random correct-length hex string is overwhelmingly unlikely to decode.

Normal mode uses:

```text
4 version bits + 28 keyed tag bits
```

So random input is accepted with probability just under:

```text
1 in 2^32
```

Boosted mode uses at least:

```text
4 version bits + 60 keyed tag bits
```

So random input is accepted with probability at most just under:

```text
1 in 2^64
```

Some boosted profiles are stronger.

That is before checking whether the decoded SQL ID actually exists.

And before authorization.

For example, with the default `uint32` normal profile, a random 16-character hex string is accepted at roughly 1 in 4.29 billion.

If your table only has 1 million rows, the chance of hitting a live row is far lower again.

And even then, the caller still has to pass your permission checks.

---

## Bad IDs should count

A bad public ID might be a typo.

It might be a stale link.

It might be a broken client.

It might be a bot.

It might be someone guessing.

Your application should treat repeated bad IDs as a signal.

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

A simple rate limit changes the economics completely.

For example:

```text
10 bad IDs per 30 minutes per bucket
```

is:

```text
175,200 guesses per year per bucket
```

At that rate, the expected time to hit any decoder-valid normal-mode handle is roughly:

```text
24,515 years per bucket
```

For the weakest boosted mode, it is roughly:

```text
105 trillion years per bucket
```

That still only means “decoder-valid”.

It does not mean “real row”.

It does not mean “authorized”.

It does not mean “access granted”.

---

# Capacity

The default `uint32` profile supports over 4.29 billion SQL IDs.

For many applications, that is plenty.

For very large systems, use `uint48` or `uint64`.

Suppose you have:

```text
100 servers
100 million IDs per server per day
```

That is:

```text
10 billion IDs per day
```

At that rate:

| Profile  |  Approximate lifetime |
| -------- | --------------------: |
| `uint32` |        about 10 hours |
| `uint48` |        about 77 years |
| `uint64` | about 5 million years |

If you partition the ID space by server, region, tenant, or shard, plan the bits deliberately.

The library gives you the public handle layer.

Your SQL ID allocation strategy remains your architecture.

---

# SQL-style aliases

The core API is:

```python
id_to_hex(123)
hex_to_id(public_hex)
validate_hex(public_hex)
```

SQL-style aliases are also included:

```python
sql_generate_id(123)
sql_decode_id(public_hex)
sql_validate_id(public_hex)
```

Use whichever reads better in your codebase.

---

# What this library is

It is a small SQL boundary tool.

It lets the database keep the thing it is good at:

```text
integer primary keys
```

And lets the outside world use the thing it wants:

```text
compact public hex handles
```

It avoids UUID primary keys when you do not need them.

It avoids lookup tables when deterministic conversion is enough.

It avoids exposing raw sequential IDs.

It keeps public IDs versioned, keyed, compact, and reversible by your application.

---

# What this library is not

It is not an authorization system.

It is not a bearer token.

It is not a password reset token.

It is not a capability URL.

It is not a reason to skip permission checks.

Decode the handle.

Load the row.

Check access.

Then proceed.

---

# The point

Use SQL integers where SQL integers shine.

Use public hex where public hex shines.

Do not force one identifier to satisfy two very different jobs.

```python
public_id = id_to_hex(row.id)
row_id = hex_to_id(public_id)
```

Fast inside.
Clean outside.
Designed for the boundary between them.
