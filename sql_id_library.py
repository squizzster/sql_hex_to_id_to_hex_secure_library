"""Layout-registry driven reversible SQL integer public IDs.

This module turns a positive SQL integer ID into a deterministic public hex ID,
and turns a valid public hex ID back into the original integer. The design is
small on purpose:

    id_to_hex(123)                    -> "16 lowercase hex chars" by default
    hex_to_id("...")                 -> 123, or None
    validate_hex("...")              -> structured success or real error detail

The encoder/decoder is driven by a fixed layout registry. Callers choose a
named profile and an optional boosted mode; callers do not provide arbitrary bit
counts.

Default public ID:

    profile="uint32", boosted=False
    4 version bits + 32 id bits + 28 keyed tag bits = 64 bits = 16 hex chars

Normal layouts:

    uint8   4 version +  8 id + 28 tag =  40 bits = 10 hex chars
    uint16  4 version + 16 id + 28 tag =  48 bits = 12 hex chars
    uint24  4 version + 24 id + 28 tag =  56 bits = 14 hex chars
    uint32  4 version + 32 id + 28 tag =  64 bits = 16 hex chars
    uint48  4 version + 48 id + 28 tag =  80 bits = 20 hex chars
    uint64  4 version + 64 id + 28 tag =  96 bits = 24 hex chars

Boosted layouts:

    uint8   4 version +  8 id + 60 tag =  72 bits = 18 hex chars
    uint16  4 version + 16 id + 68 tag =  88 bits = 22 hex chars
    uint24  4 version + 24 id + 76 tag = 104 bits = 26 hex chars
    uint32  4 version + 32 id + 76 tag = 112 bits = 28 hex chars
    uint48  4 version + 48 id + 68 tag = 120 bits = 30 hex chars
    uint64  4 version + 64 id + 60 tag = 128 bits = 32 hex chars

Decode is length-driven. Each supported hex length maps to exactly one layout;
there is no caller-supplied decode profile and no embedded boost flag.

Public format:

    SQL integer -> layout pack -> secret-keyed Feistel permutation -> hex

Plain layout before the Feistel permutation:

    [ version ][ zero-based SQL id index ][ keyed validation tag ]

SQL ID policy:

    * ID 0 is always invalid/reserved.
    * profile uintN accepts SQL IDs 1..(2**N - 1).
    * the raw all-ones id-index state is rejected, so uint32's maximum public
      SQL ID is the conventional 4_294_967_295.

Secret configuration:

    Set XCTX_ID_PASSWORD to at least 32 UTF-8 bytes of secret. Recommended:

        python -c "import secrets; print(secrets.token_hex(32))"

    Store the printed 64-hex-character value in XCTX_ID_PASSWORD. The fixed
    domain salt below is not secret; the environment value is the key.

Security model:

    This is a deterministic public-handle layer for internal SQL integer IDs. It
    hides sequential IDs and rejects almost all random/tampered inputs. It is not
    a bearer token, authentication system, authorization system, or proof of
    permission. Always check decoded IDs against normal application permissions
    and business rules.

Random-valid probability for a uniformly random string of the right length is:

    (2**id_bits - 1) / 2**total_bits

    Normal layouts are all just under 2**-32.
    Boosted layouts are at least just under 2**-64, and some are stronger.

Operational hardening:

    A real deployment should count bad public IDs as suspicious. A strong policy
    such as 10 bad IDs per session/IP/account bucket per 30 minutes caps online
    guessing to:

        10 * 2 * 24 * 365 = 175_200 guesses/year/bucket

    For normal layouts, any-profile random-valid odds are approximately 2**-32,
    so the worst-case expected time to hit any syntactically valid public ID is:

        2**32 / 175_200 ~= 24_515 years/bucket

    Boosted uint64, the least-rejecting boosted profile, is approximately
    2**-64, giving:

        2**64 / 175_200 ~= 105_289_635_123_913 years/bucket

    This rate-limit policy raises the practical online attack cost. It does not
    turn these IDs into possession-grants-access tokens. For reset links,
    magic-login links, invite tokens, download grants, API keys, sessions, or any
    bearer-token use case, use independent random tokens of at least 128 bits.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Final


ENV_PASSWORD_NAME: Final[str] = "XCTX_ID_PASSWORD"
MIN_PASSWORD_BYTES: Final[int] = 32
MIN_PASSWORD_UNIQUE_BYTES: Final[int] = 8

SCHEME_REVISION: Final[int] = 1
VERSION_BITS: Final[int] = 4
ISSUE_VERSION: Final[int] = 1
ACTIVE_DECODE_VERSIONS: Final[frozenset[int]] = frozenset({ISSUE_VERSION})

DEFAULT_PROFILE: Final[str] = "uint32"
DEFAULT_BOOSTED: Final[bool] = False
MIN_ID: Final[int] = 1
MYSQL_UNSIGNED_INT_MAX: Final[int] = (1 << 32) - 1
ROUNDS: Final[int] = 16

# Fixed 32-byte domain-separation salt. This is not secret; the environment
# secret is the secret. Changing this salt intentionally creates a new scheme.
DOMAIN_SALT_HEX: Final[str] = "0b91b4e8fd74bcb256a19d188c83470a7b75a4897babb252e54b6eb8f8bb392d"
_DOMAIN_SALT: Final[bytes] = bytes.fromhex(DOMAIN_SALT_HEX)

_DECIMAL_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9]+$")
_HEX_CHARS_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]+$")


@dataclass(frozen=True)
class SqlIdLayout:
    """A fixed public-ID layout selected by profile and mode."""

    profile: str
    mode: str
    id_bits: int
    version_bits: int
    tag_bits: int
    total_bits: int
    hex_chars: int

    @property
    def boosted(self) -> bool:
        return self.mode == "boosted"

    @property
    def bytes(self) -> int:
        return self.total_bits // 8

    @property
    def id_states(self) -> int:
        return 1 << self.id_bits

    @property
    def max_id(self) -> int:
        # ID 0 is invalid and SQL IDs are represented as zero-based indexes.
        # Rejecting the raw all-ones id-index state makes uintN max == 2**N - 1.
        return (1 << self.id_bits) - 1

    @property
    def version_mask(self) -> int:
        return (1 << self.version_bits) - 1

    @property
    def id_mask(self) -> int:
        return (1 << self.id_bits) - 1

    @property
    def tag_mask(self) -> int:
        return (1 << self.tag_bits) - 1

    @property
    def value_mask(self) -> int:
        return (1 << self.total_bits) - 1

    @property
    def tag_bytes(self) -> int:
        return (self.tag_bits + 7) // 8

    @property
    def id_bytes(self) -> int:
        return (self.id_bits + 7) // 8

    @property
    def half_bits(self) -> int:
        return self.total_bits // 2

    @property
    def half_bytes(self) -> int:
        return (self.half_bits + 7) // 8

    @property
    def half_mask(self) -> int:
        return (1 << self.half_bits) - 1

    @property
    def random_valid_probability(self) -> float:
        return self.max_id / float(1 << self.total_bits)

    def domain_label(self) -> bytes:
        """Return canonical bytes for key-domain separation."""
        return (
            f"scheme={SCHEME_REVISION};profile={self.profile};mode={self.mode};"
            f"version_bits={self.version_bits};id_bits={self.id_bits};"
            f"tag_bits={self.tag_bits};total_bits={self.total_bits};"
            f"hex_chars={self.hex_chars};issue_version={ISSUE_VERSION}"
        ).encode("ascii")


@dataclass(frozen=True)
class SqlIdValidation:
    """Structured validation result returned by validate_hex()."""

    ok: bool
    id: int | None = None
    public_hex: str | None = None
    profile: str | None = None
    mode: str | None = None
    version: int | None = None
    layout: SqlIdLayout | None = None
    error_code: str | None = None
    error: str | None = None


_LAYOUT_SPECS: Final[tuple[tuple[str, str, int, int, int, int], ...]] = (
    # profile, mode, id_bits, tag_bits, total_bits, hex_chars
    ("uint8", "normal", 8, 28, 40, 10),
    ("uint16", "normal", 16, 28, 48, 12),
    ("uint24", "normal", 24, 28, 56, 14),
    ("uint32", "normal", 32, 28, 64, 16),
    ("uint48", "normal", 48, 28, 80, 20),
    ("uint64", "normal", 64, 28, 96, 24),
    ("uint8", "boosted", 8, 60, 72, 18),
    ("uint16", "boosted", 16, 68, 88, 22),
    ("uint24", "boosted", 24, 76, 104, 26),
    ("uint32", "boosted", 32, 76, 112, 28),
    ("uint48", "boosted", 48, 68, 120, 30),
    ("uint64", "boosted", 64, 60, 128, 32),
)

LAYOUTS: Final[tuple[SqlIdLayout, ...]] = tuple(
    SqlIdLayout(
        profile=profile,
        mode=mode,
        id_bits=id_bits,
        version_bits=VERSION_BITS,
        tag_bits=tag_bits,
        total_bits=total_bits,
        hex_chars=hex_chars,
    )
    for profile, mode, id_bits, tag_bits, total_bits, hex_chars in _LAYOUT_SPECS
)

LAYOUTS_BY_PROFILE_MODE: Final[dict[tuple[str, str], SqlIdLayout]] = {
    (layout.profile, layout.mode): layout for layout in LAYOUTS
}
LAYOUTS_BY_HEX_LENGTH: Final[dict[int, SqlIdLayout]] = {
    layout.hex_chars: layout for layout in LAYOUTS
}
SUPPORTED_PROFILES: Final[tuple[str, ...]] = ("uint8", "uint16", "uint24", "uint32", "uint48", "uint64")
SUPPORTED_HEX_LENGTHS: Final[tuple[int, ...]] = tuple(sorted(LAYOUTS_BY_HEX_LENGTH))
DEFAULT_LAYOUT: Final[SqlIdLayout] = LAYOUTS_BY_PROFILE_MODE[(DEFAULT_PROFILE, "normal")]
MAX_ID: Final[int] = DEFAULT_LAYOUT.max_id
ID_BITS: Final[int] = DEFAULT_LAYOUT.id_bits
TAG_BITS: Final[int] = DEFAULT_LAYOUT.tag_bits

# Hard caps for untrusted string inputs. Public IDs are at most 32 hex chars,
# and uint64 decimal IDs need 20 digits; 32 leaves room for leading-zero padding.
_MAX_PUBLIC_HEX_CHARS: Final[int] = max(SUPPORTED_HEX_LENGTHS)
_MAX_DECIMAL_ID_STRING_CHARS: Final[int] = 32

__all__ = [
    "ACTIVE_DECODE_VERSIONS",
    "DEFAULT_BOOSTED",
    "DEFAULT_LAYOUT",
    "DEFAULT_PROFILE",
    "DOMAIN_SALT_HEX",
    "ENV_PASSWORD_NAME",
    "ID_BITS",
    "ISSUE_VERSION",
    "LAYOUTS",
    "LAYOUTS_BY_HEX_LENGTH",
    "LAYOUTS_BY_PROFILE_MODE",
    "MAX_ID",
    "MIN_ID",
    "MIN_PASSWORD_BYTES",
    "MYSQL_UNSIGNED_INT_MAX",
    "ROUNDS",
    "SUPPORTED_HEX_LENGTHS",
    "SUPPORTED_PROFILES",
    "SCHEME_REVISION",
    "SqlIdLayout",
    "SqlIdValidation",
    "TAG_BITS",
    "VERSION_BITS",
    "available_layouts",
    "hex_to_id",
    "hex_to_parts",
    "id_to_hex",
    "is_configured",
    "layout_for_hex_length",
    "layout_for_profile",
    "sql_decode_id",
    "sql_generate_id",
    "sql_validate_id",
    "validate_hex",
]


class _ConfigError(ValueError):
    """Internal configuration error surfaced by validate_hex()."""


class _InputError(ValueError):
    """Internal input error converted to None by convenience APIs."""


class _ValidationFailure(ValueError):
    """Internal decode failure with a stable public error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _registry_is_sane() -> bool:
    """Return True when the fixed layout registry is internally consistent."""
    if VERSION_BITS != 4:
        return False
    if not 0 <= ISSUE_VERSION <= ((1 << VERSION_BITS) - 1):
        return False
    if ISSUE_VERSION not in ACTIVE_DECODE_VERSIONS:
        return False
    if ACTIVE_DECODE_VERSIONS != frozenset({ISSUE_VERSION}):
        return False
    if len(_DOMAIN_SALT) != 32:
        return False
    if ROUNDS < 12:
        return False
    if MIN_ID != 1:
        return False
    if MYSQL_UNSIGNED_INT_MAX != (1 << 32) - 1:
        return False
    if DEFAULT_LAYOUT.profile != "uint32" or DEFAULT_LAYOUT.mode != "normal":
        return False
    if DEFAULT_LAYOUT.total_bits != 64 or DEFAULT_LAYOUT.hex_chars != 16:
        return False
    if DEFAULT_LAYOUT.id_bits != 32 or DEFAULT_LAYOUT.tag_bits != 28:
        return False
    if len(LAYOUTS) != 12:
        return False
    if len(LAYOUTS_BY_PROFILE_MODE) != len(LAYOUTS):
        return False
    if len(LAYOUTS_BY_HEX_LENGTH) != len(LAYOUTS):
        return False

    expected_profiles = set(SUPPORTED_PROFILES)
    seen_profiles = {layout.profile for layout in LAYOUTS}
    if seen_profiles != expected_profiles:
        return False

    for profile in SUPPORTED_PROFILES:
        if (profile, "normal") not in LAYOUTS_BY_PROFILE_MODE:
            return False
        if (profile, "boosted") not in LAYOUTS_BY_PROFILE_MODE:
            return False

    for layout in LAYOUTS:
        if layout.mode not in {"normal", "boosted"}:
            return False
        if layout.version_bits != VERSION_BITS:
            return False
        if layout.total_bits != layout.version_bits + layout.id_bits + layout.tag_bits:
            return False
        if layout.total_bits % 8 != 0:
            return False
        if layout.total_bits % 2 != 0:
            return False
        if layout.hex_chars != layout.total_bits // 4:
            return False
        if layout.bytes * 8 != layout.total_bits:
            return False
        if not layout.profile.startswith("uint"):
            return False
        try:
            profile_bits = int(layout.profile[4:])
        except ValueError:
            return False
        if profile_bits != layout.id_bits:
            return False
        if layout.max_id != (1 << layout.id_bits) - 1:
            return False
        if layout.max_id < MIN_ID:
            return False
        if layout.mode == "normal" and layout.tag_bits != 28:
            return False
        if layout.mode == "boosted" and layout.tag_bits < 60:
            return False
        if layout.half_bits > 256:
            return False

    return True


# Backwards-readable name for tests and users who introspect internals.
def _constants_are_sane() -> bool:
    """Return True when constants and the fixed registry are valid."""
    return _registry_is_sane()


def available_layouts() -> tuple[SqlIdLayout, ...]:
    """Return the fixed supported layouts."""
    return LAYOUTS


def layout_for_profile(profile: object = DEFAULT_PROFILE, *, boosted: object = DEFAULT_BOOSTED) -> SqlIdLayout | None:
    """Return the layout for a fixed profile/mode, or None for invalid input."""
    try:
        return _resolve_layout(profile, boosted=boosted)
    except Exception:
        return None


def layout_for_hex_length(hex_chars: object) -> SqlIdLayout | None:
    """Return the unique decode layout for a public hex length, or None."""
    if isinstance(hex_chars, bool) or not isinstance(hex_chars, int):
        return None
    return LAYOUTS_BY_HEX_LENGTH.get(hex_chars)


def _password_bytes() -> bytes:
    """Return configured password bytes or raise an internal config error."""
    password = os.environ.get(ENV_PASSWORD_NAME)
    if not isinstance(password, str):
        raise _ConfigError(f"{ENV_PASSWORD_NAME} is required")

    password_bytes = password.encode("utf-8")
    if len(password_bytes) < MIN_PASSWORD_BYTES:
        raise _ConfigError(f"{ENV_PASSWORD_NAME} must be at least {MIN_PASSWORD_BYTES} bytes")
    if len(set(password_bytes)) < MIN_PASSWORD_UNIQUE_BYTES:
        raise _ConfigError(f"{ENV_PASSWORD_NAME} has too little byte diversity")
    return password_bytes


@lru_cache(maxsize=64)
def _derive_material(password_bytes: bytes, layout: SqlIdLayout) -> tuple[tuple[bytes, ...], bytes]:
    """Derive layout-specific Feistel round keys and validation-tag key."""
    seed = hmac.new(
        password_bytes,
        _DOMAIN_SALT + b":xctx-sql-id-layout-registry:" + layout.domain_label() + b":seed:",
        hashlib.sha256,
    ).digest()

    outer_round_keys = tuple(
        hmac.new(
            seed,
            b":outer-feistel-round:" + round_id.to_bytes(2, "big"),
            hashlib.sha256,
        ).digest()
        for round_id in range(ROUNDS)
    )

    tag_key = hmac.new(
        seed,
        b":keyed-validation-tag:" + layout.tag_bits.to_bytes(2, "big"),
        hashlib.sha256,
    ).digest()
    return outer_round_keys, tag_key


def _key_material(layout: SqlIdLayout = DEFAULT_LAYOUT) -> tuple[tuple[bytes, ...], bytes]:
    """Return configured key material for a layout or raise an internal error."""
    if not _registry_is_sane():
        raise _ConfigError("invalid sql_id_library layout registry")
    return _derive_material(_password_bytes(), layout)


def is_configured() -> bool:
    """Return whether the module has enough configuration to encode/decode IDs."""
    try:
        _key_material(DEFAULT_LAYOUT)
        return True
    except Exception:  # noqa: BLE001 - configuration probe must not crash callers
        return False


def _resolve_layout(profile: object = DEFAULT_PROFILE, *, boosted: object = DEFAULT_BOOSTED) -> SqlIdLayout:
    """Strictly resolve public profile/mode arguments into a fixed layout."""
    if not isinstance(profile, str):
        raise _InputError("profile must be one of: " + ", ".join(SUPPORTED_PROFILES))
    profile_key = profile.lower()
    if profile_key not in SUPPORTED_PROFILES:
        raise _InputError("profile must be one of: " + ", ".join(SUPPORTED_PROFILES))
    if not isinstance(boosted, bool):
        raise _InputError("boosted must be a bool")
    mode = "boosted" if boosted else "normal"
    return LAYOUTS_BY_PROFILE_MODE[(profile_key, mode)]


def _coerce_id(value: object, layout: SqlIdLayout) -> int:
    """Strictly coerce a public input into an integer SQL ID for a layout."""
    if isinstance(value, bool):
        raise _InputError("bool is not an id")
    if isinstance(value, int):
        id_value = value
    elif isinstance(value, str):
        if len(value) > _MAX_DECIMAL_ID_STRING_CHARS:
            raise _InputError("id string is too long")
        if not _DECIMAL_RE.fullmatch(value):
            raise _InputError("id must be an int or decimal digit string")
        max_digits = len(str(layout.max_id))
        significant_digits = value.lstrip("0") or "0"
        if len(significant_digits) > max_digits:
            raise _InputError("id string too long for profile")
        id_value = int(value)
    else:
        raise _InputError("id must be an int or decimal digit string")

    if not MIN_ID <= id_value <= layout.max_id:
        raise _InputError(f"id is outside profile range 1..{layout.max_id}")
    return id_value


def _round_function(right: int, key: bytes, layout: SqlIdLayout) -> int:
    """Return a deterministic half-width Feistel round output."""
    digest = hmac.new(key, right.to_bytes(layout.half_bytes, "big"), hashlib.sha256).digest()
    return int.from_bytes(digest[: layout.half_bytes], "big") & layout.half_mask


def _feistel_encrypt(value: int, round_keys: tuple[bytes, ...], layout: SqlIdLayout) -> int:
    """Encrypt one layout-width integer using the secret-derived Feistel PRP."""
    if not 0 <= value <= layout.value_mask:
        raise ValueError("value is outside layout range")

    left = (value >> layout.half_bits) & layout.half_mask
    right = value & layout.half_mask

    for key in round_keys:
        left, right = right, (left ^ _round_function(right, key, layout)) & layout.half_mask

    return ((left << layout.half_bits) | right) & layout.value_mask


def _feistel_decrypt(value: int, round_keys: tuple[bytes, ...], layout: SqlIdLayout) -> int:
    """Decrypt one layout-width integer using the secret-derived Feistel PRP."""
    if not 0 <= value <= layout.value_mask:
        raise ValueError("value is outside layout range")

    left = (value >> layout.half_bits) & layout.half_mask
    right = value & layout.half_mask

    for key in reversed(round_keys):
        left, right = (right ^ _round_function(left, key, layout)) & layout.half_mask, left

    return ((left << layout.half_bits) | right) & layout.value_mask


# Compatibility-shaped private helpers for the default uint32 normal layout.
def _feistel_encrypt64(value: int, round_keys: tuple[bytes, ...]) -> int:
    """Encrypt one default-layout 64-bit integer."""
    return _feistel_encrypt(value, round_keys, DEFAULT_LAYOUT)


def _feistel_decrypt64(value: int, round_keys: tuple[bytes, ...]) -> int:
    """Decrypt one default-layout 64-bit integer."""
    return _feistel_decrypt(value, round_keys, DEFAULT_LAYOUT)


def _tag(version: int, id_index: int, tag_key: bytes, layout: SqlIdLayout) -> int:
    """Return a keyed validation tag for the layout/version/id-index tuple."""
    if not 0 <= version <= layout.version_mask:
        raise ValueError("version out of range")
    if not 0 <= id_index <= layout.id_mask:
        raise ValueError("id index out of range")

    message = (
        layout.domain_label()
        + b":version:"
        + version.to_bytes(1, "big")
        + b":id-index:"
        + id_index.to_bytes(layout.id_bytes, "big")
    )
    digest = hmac.new(tag_key, message, hashlib.sha256).digest()
    return int.from_bytes(digest[: layout.tag_bytes], "big") & layout.tag_mask


def _tag28(version: int, id_index: int, tag_key: bytes) -> int:
    """Return a default-layout 28-bit validation tag."""
    return _tag(version, id_index, tag_key, DEFAULT_LAYOUT)


def _tags_equal(left: int, right: int, layout: SqlIdLayout = DEFAULT_LAYOUT) -> bool:
    """Compare compact integer tags without data-dependent short-circuiting."""
    return hmac.compare_digest(
        (left & layout.tag_mask).to_bytes(layout.tag_bytes, "big"),
        (right & layout.tag_mask).to_bytes(layout.tag_bytes, "big"),
    )


def _pack_plain(version: int, id_index: int, tag_key: bytes, layout: SqlIdLayout) -> int:
    """Pack version, zero-based SQL ID index, and keyed tag into layout bits."""
    if not 0 <= version <= layout.version_mask:
        raise ValueError("version out of range")
    if not 0 <= id_index < layout.max_id:
        raise ValueError("id index out of public range")

    tag = _tag(version, id_index, tag_key, layout)
    return (
        ((version & layout.version_mask) << (layout.id_bits + layout.tag_bits))
        | ((id_index & layout.id_mask) << layout.tag_bits)
        | tag
    ) & layout.value_mask


def _unpack_plain(value: int, layout: SqlIdLayout) -> tuple[int, int, int]:
    """Unpack a layout-width integer into version, zero-based ID index, and tag."""
    if not 0 <= value <= layout.value_mask:
        raise ValueError("value is outside layout range")

    version = (value >> (layout.id_bits + layout.tag_bits)) & layout.version_mask
    id_index = (value >> layout.tag_bits) & layout.id_mask
    tag = value & layout.tag_mask
    return version, id_index, tag


def _pack_plain64(version: int, id_index: int, tag_key: bytes) -> int:
    """Pack a default-layout 64-bit plaintext value."""
    return _pack_plain(version, id_index, tag_key, DEFAULT_LAYOUT)


def _unpack_plain64(value: int) -> tuple[int, int, int]:
    """Unpack a default-layout 64-bit plaintext value."""
    return _unpack_plain(value, DEFAULT_LAYOUT)


def id_to_hex(value: object, *, profile: object = DEFAULT_PROFILE, boosted: object = DEFAULT_BOOSTED) -> str | None:
    """Return a lowercase public hex ID for an integer, or None on any failure."""
    try:
        layout = _resolve_layout(profile, boosted=boosted)
        id_value = _coerce_id(value, layout)
        round_keys, tag_key = _key_material(layout)
        plain = _pack_plain(ISSUE_VERSION, id_value - 1, tag_key, layout)
        encrypted = _feistel_encrypt(plain, round_keys, layout)
        return f"{encrypted:0{layout.hex_chars}x}"
    except Exception:  # noqa: BLE001 - public convenience API returns None
        return None


def sql_generate_id(
    id_required: object,
    *,
    profile: object = DEFAULT_PROFILE,
    boosted: object = DEFAULT_BOOSTED,
) -> str | None:
    """Alias for id_to_hex(): give me hex from an id."""
    return id_to_hex(id_required, profile=profile, boosted=boosted)


def _validation_error(
    code: str,
    message: str,
    *,
    public_hex: str | None = None,
    layout: SqlIdLayout | None = None,
    version: int | None = None,
) -> SqlIdValidation:
    return SqlIdValidation(
        ok=False,
        public_hex=public_hex,
        profile=layout.profile if layout else None,
        mode=layout.mode if layout else None,
        version=version,
        layout=layout,
        error_code=code,
        error=message,
    )


def _public_hex_for_length_error(value: str) -> str | None:
    """Return normalized error echo for bounded inputs, without copying huge strings."""
    if len(value) > _MAX_PUBLIC_HEX_CHARS:
        return None
    return value.lower()


def _decode_public_hex(value: object) -> SqlIdValidation:
    """Decode and validate a public hex ID, returning success or failure detail."""
    if not isinstance(value, str):
        return _validation_error("not_string", "public id must be a hex string")

    if value == "":
        return _validation_error(
            "unsupported_length",
            "public id length must be one of: " + ", ".join(map(str, SUPPORTED_HEX_LENGTHS)),
            public_hex=value,
        )

    layout = LAYOUTS_BY_HEX_LENGTH.get(len(value))
    if layout is None:
        return _validation_error(
            "unsupported_length",
            "public id length must be one of: " + ", ".join(map(str, SUPPORTED_HEX_LENGTHS)),
            public_hex=_public_hex_for_length_error(value),
        )

    if not _HEX_CHARS_RE.fullmatch(value):
        return _validation_error("invalid_hex", "public id must contain only hex characters", public_hex=value)

    public_hex = value.lower()

    try:
        round_keys, tag_key = _key_material(layout)
        encrypted = int(public_hex, 16)
        plain = _feistel_decrypt(encrypted, round_keys, layout)
        version, id_index, supplied_tag = _unpack_plain(plain, layout)

        if version not in ACTIVE_DECODE_VERSIONS:
            raise _ValidationFailure("unsupported_version", "public id uses an inactive version")
        if not 0 <= id_index < layout.max_id:
            raise _ValidationFailure("id_out_of_range", "decoded id is outside this profile's public range")

        expected_tag = _tag(version, id_index, tag_key, layout)
        if not _tags_equal(supplied_tag, expected_tag, layout):
            raise _ValidationFailure("tag_mismatch", "public id validation tag does not match")

        id_value = id_index + 1
        if not MIN_ID <= id_value <= layout.max_id:
            raise _ValidationFailure("id_out_of_range", "decoded id is outside this profile's public range")

        return SqlIdValidation(
            ok=True,
            id=id_value,
            public_hex=public_hex,
            profile=layout.profile,
            mode=layout.mode,
            version=version,
            layout=layout,
        )
    except _ConfigError as exc:
        return _validation_error("bad_config", str(exc), public_hex=public_hex, layout=layout)
    except _ValidationFailure as exc:
        return _validation_error(exc.code, exc.message, public_hex=public_hex, layout=layout)
    except Exception as exc:  # noqa: BLE001 - validation returns a real error, not an exception
        return _validation_error("internal_error", f"internal validation failure: {exc}", public_hex=public_hex, layout=layout)


def validate_hex(value: object) -> SqlIdValidation:
    """Validate a public hex ID and return structured success/error detail."""
    return _decode_public_hex(value)


def sql_validate_id(value: object) -> SqlIdValidation:
    """Alias for validate_hex(): validate a hex and report a real error."""
    return validate_hex(value)


def hex_to_id(value: object) -> int | None:
    """Return the original integer for a public hex ID, or None on any failure."""
    result = validate_hex(value)
    return result.id if result.ok else None


def sql_decode_id(value: object) -> int | None:
    """Alias for hex_to_id(): give me id from a hex."""
    return hex_to_id(value)


def hex_to_parts(value: object) -> tuple[str, str, int, int] | None:
    """Return (profile, mode, version, integer_id) for a valid public ID, or None."""
    result = validate_hex(value)
    if not result.ok or result.id is None or result.profile is None or result.mode is None or result.version is None:
        return None
    return result.profile, result.mode, result.version, result.id
