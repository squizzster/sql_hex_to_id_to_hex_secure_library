"""Reversible 32-hex-character public IDs for SQL BIGINT integer keys.

This module turns a positive SQL integer ID, with optional label bits, into a
deterministic public hex ID. It turns a valid public hex ID back into the
original integer only through the exact expected-label decoder. The public ID is
always 32 lowercase hex characters:

    3 version bits + 5 label bits + 1 range bit + id bits + keyed tag bits
    = 128 bits

Label ``0`` is the unlabeled mode used by ``id_to_hex()`` and
``hex_to_id()``. Labels ``1..30`` are typed/table/bucket labels used only by the
explicit labeled API. Label ``31`` is reserved.

Plain layout before the Feistel permutation:

    [ version ][ label ][ canonical range ][ SQL id ][ keyed validation tag ]

The range bit is an internal canonical encoding choice for BIGINT UNSIGNED IDs:

    range 0: SQL IDs 1..2**32 - 1 use a 32-bit ID field and an 87-bit tag
    range 1: SQL IDs 2**32..2**64 - 1 use a 64-bit ID field and a 55-bit tag

Every positive BIGINT UNSIGNED value has exactly one canonical public encoding.

The keyed validation tag covers the scheme, bit layout, version, label, range,
and SQL ID. A valid labeled ID cannot be reinterpreted as unlabeled, and a valid
ID for one label cannot be decoded by asking for another label.

Security model:

    This is a deterministic public-handle layer for internal SQL integer IDs. It
    hides sequential IDs and rejects almost all random/tampered inputs. It is not
    a bearer token, authentication system, authorization system, or proof of
    permission. Always check decoded IDs against normal application permissions
    and business rules.

Strict decoder probability:

    The integer-returning APIs always check one exact expected label:

        hex_to_id(public_hex)                 expects label 0
        hex_to_id_label(public_hex, label)    expects the supplied label,
                                              which must resolve to 1..30

    For one expected label, random-valid probability is:

        (2**64 - 1) / 2**128, just under 2**-64

Generic inspection:

    ``inspect_hex()`` and ``hex_to_parts()`` are diagnostic helpers. They accept
    any valid non-reserved label, so they are intentionally not the enforcement
    API for typed routes.

Secret configuration:

    This v4 scheme requires three independent inputs: DOMAIN_SALT_HEX,
    XCTX_ID_PASSWORD, and a disk pepper file. Replace DOMAIN_SALT_HEX near the
    top of this file with a deployment-specific 32-byte random hex string, set
    XCTX_ID_PASSWORD to at least 32 UTF-8 bytes, and create the pepper file
    configured by ``pepper_file_location``.

    Generate each value independently:

        python -c "import secrets; print(secrets.token_hex(32))"

    The bundled domain salt is public. A private deployment-specific salt is
    useful hardening, but it is not a substitute for the password or pepper.
    Changing any of the salt, password, or pepper after issuing IDs makes
    existing public IDs stop decoding.

Operational hardening:

    A real deployment should count bad public IDs as suspicious. A strong policy
    such as 10 bad IDs per session/IP/account bucket per 30 minutes caps online
    guessing to:

        10 * 2 * 24 * 365 = 175_200 guesses/year/bucket

    For strict expected-label decoding, random-valid odds are just under 2**-64,
    so the worst-case expected time to hit any decoder-valid public ID is:

        2**64 / 175_200 ~= 105_289_635_123_913 years/bucket

    This rate-limit policy raises the practical online attack cost. It does not
    turn these IDs into possession-grants-access tokens. For reset links,
    magic-login links, invite tokens, download grants, API keys, sessions, or any
    bearer-token use case, use independent random tokens of at least 128 bits.
"""

from __future__ import annotations

import hashlib
import hmac
import errno
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Final


ENV_PASSWORD_NAME: Final[str] = "XCTX_ID_PASSWORD"
MIN_PASSWORD_BYTES: Final[int] = 32
MIN_PASSWORD_UNIQUE_BYTES: Final[int] = 8
PEPPER_FILE_LOCATION_KEY: Final[str] = "pepper_file_location"
LABELS_CONFIG_KEY: Final[str] = "labels"
DEFAULT_PEPPER_FILE_LOCATION: Final[str] = "~/.sql_hex_id_pepper_file.key"
MIN_PEPPER_HEX_CHARS: Final[int] = 64
MAX_PEPPER_HEX_CHARS: Final[int] = 256
MIN_PEPPER_BYTES: Final[int] = 32
MAX_PEPPER_BYTES: Final[int] = 128
MIN_PEPPER_UNIQUE_BYTES: Final[int] = 8

SCHEME_REVISION: Final[int] = 4
VERSION_BITS: Final[int] = 3
LABEL_BITS: Final[int] = 5
RANGE_BITS: Final[int] = 1
SMALL_RANGE_CLASS: Final[int] = 0
BIGINT_RANGE_CLASS: Final[int] = 1
SMALL_ID_BITS: Final[int] = 32
BIGINT_ID_BITS: Final[int] = 64
TOTAL_BITS: Final[int] = 128
HEX_CHARS: Final[int] = 32
SMALL_TAG_BITS: Final[int] = TOTAL_BITS - VERSION_BITS - LABEL_BITS - RANGE_BITS - SMALL_ID_BITS
BIGINT_TAG_BITS: Final[int] = TOTAL_BITS - VERSION_BITS - LABEL_BITS - RANGE_BITS - BIGINT_ID_BITS
ID_BITS: Final[int] = BIGINT_ID_BITS
TAG_BITS: Final[int] = BIGINT_TAG_BITS

ISSUE_VERSION: Final[int] = 2
NO_LABEL: Final[int] = 0
RESERVED_VERSION: Final[int] = (1 << VERSION_BITS) - 1
RESERVED_LABEL: Final[int] = (1 << LABEL_BITS) - 1
MAX_LABEL: Final[int] = RESERVED_LABEL - 1
MIN_ID: Final[int] = 1
SMALL_RANGE_MAX_ID: Final[int] = (1 << SMALL_ID_BITS) - 1
BIGINT_RANGE_MIN_ID: Final[int] = SMALL_RANGE_MAX_ID + 1
MAX_ID: Final[int] = (1 << BIGINT_ID_BITS) - 1
MYSQL_UNSIGNED_BIGINT_MAX: Final[int] = MAX_ID
ROUNDS: Final[int] = 16

ACTIVE_DECODE_VERSIONS: Final[frozenset[int]] = frozenset({ISSUE_VERSION})
SUPPORTED_HEX_LENGTHS: Final[tuple[int, ...]] = (HEX_CHARS,)

# Deployment-specific 32-byte domain-separation salt.
#
# The bundled value is public and accepted for library/demo use, but deployed
# applications should replace it with a private random value generated with:
#
#     python -c "import secrets; print(secrets.token_hex(32))"
#
# Generate this independently from XCTX_ID_PASSWORD and the pepper file.
# Changing any of those values after issuing public IDs intentionally creates a
# new scheme and breaks old IDs.
DOMAIN_SALT_HEX: Final[str] = "0b91b4e8fd74bcb256a19d188c83470a7b75a4897babb252e54b6eb8f8bb392d"
_DOMAIN_SALT: Final[bytes] = bytes.fromhex(DOMAIN_SALT_HEX)

_DECIMAL_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9]+$")
_HEX_CHARS_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]+$")
_LABEL_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


@dataclass(frozen=True)
class SqlIdRangeLayout:
    """One canonical ID range inside the fixed public-ID layout."""

    range_class: int
    min_id: int
    max_id: int
    id_bits: int
    tag_bits: int

    @property
    def id_states(self) -> int:
        return 1 << self.id_bits

    @property
    def valid_id_count(self) -> int:
        return self.max_id - self.min_id + 1

    @property
    def id_mask(self) -> int:
        return (1 << self.id_bits) - 1

    @property
    def tag_mask(self) -> int:
        return (1 << self.tag_bits) - 1

    @property
    def id_bytes(self) -> int:
        return (self.id_bits + 7) // 8

    @property
    def tag_bytes(self) -> int:
        return (self.tag_bits + 7) // 8

    def domain_label(self) -> bytes:
        """Return canonical bytes for this range class."""
        return (
            f"range={self.range_class};min_id={self.min_id};"
            f"max_id={self.max_id};id_bits={self.id_bits};"
            f"tag_bits={self.tag_bits}"
        ).encode("ascii")


@dataclass(frozen=True)
class SqlIdLayout:
    """The fixed 128-bit public-ID layout."""

    version_bits: int
    label_bits: int
    range_bits: int
    total_bits: int
    hex_chars: int
    ranges: tuple[SqlIdRangeLayout, ...]

    @property
    def bytes(self) -> int:
        return self.total_bits // 8

    @property
    def id_states(self) -> int:
        return 1 << self.id_bits

    @property
    def max_id(self) -> int:
        return max(range_layout.max_id for range_layout in self.ranges)

    @property
    def valid_id_count(self) -> int:
        return sum(range_layout.valid_id_count for range_layout in self.ranges)

    @property
    def id_bits(self) -> int:
        return max(range_layout.id_bits for range_layout in self.ranges)

    @property
    def min_tag_bits(self) -> int:
        return min(range_layout.tag_bits for range_layout in self.ranges)

    @property
    def max_tag_bits(self) -> int:
        return max(range_layout.tag_bits for range_layout in self.ranges)

    @property
    def version_mask(self) -> int:
        return (1 << self.version_bits) - 1

    @property
    def label_mask(self) -> int:
        return (1 << self.label_bits) - 1

    @property
    def range_mask(self) -> int:
        return (1 << self.range_bits) - 1

    @property
    def value_mask(self) -> int:
        return (1 << self.total_bits) - 1

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
    def random_valid_probability_for_expected_label(self) -> float:
        return self.valid_id_count / float(1 << self.total_bits)

    @property
    def random_valid_probability_for_any_label(self) -> float:
        return ((MAX_LABEL + 1) * self.valid_id_count) / float(1 << self.total_bits)

    @property
    def header_bits(self) -> int:
        return self.version_bits + self.label_bits + self.range_bits

    def range_for_class(self, range_class: int) -> SqlIdRangeLayout:
        """Return range metadata for an encoded range class."""
        for range_layout in self.ranges:
            if range_layout.range_class == range_class:
                return range_layout
        raise ValueError(f"unsupported range class: {range_class}")

    def range_for_id(self, id_value: int) -> SqlIdRangeLayout:
        """Return the canonical range class for one SQL ID."""
        for range_layout in self.ranges:
            if range_layout.min_id <= id_value <= range_layout.max_id:
                return range_layout
        raise ValueError(f"id is outside range {MIN_ID}..{self.max_id}")

    def domain_label(self) -> bytes:
        """Return canonical bytes for key-domain separation."""
        ranges = b"|".join(range_layout.domain_label() for range_layout in self.ranges)
        return (
            f"scheme={SCHEME_REVISION};version_bits={self.version_bits};"
            f"label_bits={self.label_bits};range_bits={self.range_bits};"
            f"total_bits={self.total_bits};"
            f"hex_chars={self.hex_chars};issue_version={ISSUE_VERSION};"
            f"no_label={NO_LABEL};max_label={MAX_LABEL};"
            f"reserved_label={RESERVED_LABEL};reserved_version={RESERVED_VERSION}"
            ";ranges="
        ).encode("ascii") + ranges


@dataclass(frozen=True)
class SqlIdValidation:
    """Structured validation result returned by validate/inspect helpers."""

    ok: bool
    id: int | None = None
    public_hex: str | None = None
    label_id: int | None = None
    label: str | None = None
    range_class: int | None = None
    tag_bits: int | None = None
    version: int | None = None
    layout: SqlIdLayout | None = None
    error_code: str | None = None
    error: str | None = None


SMALL_RANGE_LAYOUT: Final[SqlIdRangeLayout] = SqlIdRangeLayout(
    range_class=SMALL_RANGE_CLASS,
    min_id=MIN_ID,
    max_id=SMALL_RANGE_MAX_ID,
    id_bits=SMALL_ID_BITS,
    tag_bits=SMALL_TAG_BITS,
)
BIGINT_RANGE_LAYOUT: Final[SqlIdRangeLayout] = SqlIdRangeLayout(
    range_class=BIGINT_RANGE_CLASS,
    min_id=BIGINT_RANGE_MIN_ID,
    max_id=MAX_ID,
    id_bits=BIGINT_ID_BITS,
    tag_bits=BIGINT_TAG_BITS,
)
DEFAULT_LAYOUT: Final[SqlIdLayout] = SqlIdLayout(
    version_bits=VERSION_BITS,
    label_bits=LABEL_BITS,
    range_bits=RANGE_BITS,
    total_bits=TOTAL_BITS,
    hex_chars=HEX_CHARS,
    ranges=(SMALL_RANGE_LAYOUT, BIGINT_RANGE_LAYOUT),
)
LAYOUT: Final[SqlIdLayout] = DEFAULT_LAYOUT
MAX_PUBLIC_HEX_CHARS: Final[int] = HEX_CHARS

# Hard caps for untrusted string inputs. Public IDs are exactly 32 hex chars,
# and uint64 decimal IDs need 20 digits; 32 leaves room for leading-zero padding.
_MAX_PUBLIC_HEX_CHARS: Final[int] = HEX_CHARS
_MAX_DECIMAL_ID_STRING_CHARS: Final[int] = 32
_MAX_CONFIG_FILE_BYTES: Final[int] = 2000
_MAX_PEPPER_FILE_BYTES: Final[int] = MAX_PEPPER_HEX_CHARS + 128

_CONFIG_LOCK = RLock()
_PEPPER_FILE_LOCATION: str = DEFAULT_PEPPER_FILE_LOCATION
_PEPPER_CACHE: tuple[Path, bytes] | None = None
_LABELS_BY_NAME: Mapping[str, int] = MappingProxyType({})
_LABEL_NAMES_BY_ID: Mapping[int, str] = MappingProxyType({})
_CONFIG_FILE_CACHE: dict[Path, Mapping[str, object]] = {}

__all__ = [
    "ACTIVE_DECODE_VERSIONS",
    "DEFAULT_LAYOUT",
    "DEFAULT_PEPPER_FILE_LOCATION",
    "DOMAIN_SALT_HEX",
    "ENV_PASSWORD_NAME",
    "HEX_CHARS",
    "BIGINT_ID_BITS",
    "BIGINT_RANGE_CLASS",
    "BIGINT_RANGE_LAYOUT",
    "BIGINT_RANGE_MIN_ID",
    "BIGINT_TAG_BITS",
    "ID_BITS",
    "ISSUE_VERSION",
    "LABEL_BITS",
    "LABELS_CONFIG_KEY",
    "LAYOUT",
    "MAX_ID",
    "MAX_LABEL",
    "MAX_PEPPER_BYTES",
    "MAX_PEPPER_HEX_CHARS",
    "MIN_ID",
    "MIN_PEPPER_BYTES",
    "MIN_PEPPER_HEX_CHARS",
    "MIN_PASSWORD_BYTES",
    "MYSQL_UNSIGNED_BIGINT_MAX",
    "NO_LABEL",
    "PEPPER_FILE_LOCATION_KEY",
    "RANGE_BITS",
    "RESERVED_LABEL",
    "RESERVED_VERSION",
    "ROUNDS",
    "SCHEME_REVISION",
    "SMALL_ID_BITS",
    "SMALL_RANGE_CLASS",
    "SMALL_RANGE_LAYOUT",
    "SMALL_RANGE_MAX_ID",
    "SMALL_TAG_BITS",
    "SUPPORTED_HEX_LENGTHS",
    "SqlIdLayout",
    "SqlIdRangeLayout",
    "SqlIdValidation",
    "TAG_BITS",
    "TOTAL_BITS",
    "VERSION_BITS",
    "available_labels",
    "clear_sql_id_config",
    "configure_sql_id",
    "configured_pepper_file_location",
    "hex_to_id",
    "hex_to_id_label",
    "hex_to_parts",
    "id_to_hex",
    "id_to_hex_label",
    "inspect_hex",
    "is_configured",
    "layout_for_hex_length",
    "load_sql_id_config_from_file",
    "reload_sql_id_pepper",
    "reload_sql_id_config_from_file",
    "sql_decode_id",
    "sql_decode_id_label",
    "sql_generate_id",
    "sql_generate_id_label",
    "sql_validate_id",
    "sql_validate_id_label",
    "validate_hex",
    "validate_hex_label",
]


class _ConfigError(ValueError):
    """Internal configuration error surfaced by validation helpers."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class _InputError(ValueError):
    """Internal input error converted to None by convenience APIs."""


class _ValidationFailure(ValueError):
    """Internal decode failure with a stable public error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _registry_is_sane() -> bool:
    """Return True when the fixed layout and reserved ranges are consistent."""
    if len(_DOMAIN_SALT) != 32:
        return False
    if ROUNDS < 12:
        return False
    if VERSION_BITS != 3 or LABEL_BITS != 5 or RANGE_BITS != 1:
        return False
    if SMALL_ID_BITS != 32 or BIGINT_ID_BITS != 64:
        return False
    if ID_BITS != BIGINT_ID_BITS or TAG_BITS != BIGINT_TAG_BITS:
        return False
    if SMALL_TAG_BITS != 87 or BIGINT_TAG_BITS != 55:
        return False
    if TOTAL_BITS != 128 or HEX_CHARS != 32:
        return False
    if DEFAULT_LAYOUT.total_bits != TOTAL_BITS or DEFAULT_LAYOUT.hex_chars != HEX_CHARS:
        return False
    if DEFAULT_LAYOUT.bytes != 16 or DEFAULT_LAYOUT.half_bits != 64:
        return False
    if SCHEME_REVISION != 4:
        return False
    if ISSUE_VERSION != 2:
        return False
    if not 1 <= ISSUE_VERSION < RESERVED_VERSION:
        return False
    if ACTIVE_DECODE_VERSIONS != frozenset({ISSUE_VERSION}):
        return False
    if NO_LABEL != 0 or RESERVED_LABEL != 31 or MAX_LABEL != 30:
        return False
    if SMALL_RANGE_CLASS != 0 or BIGINT_RANGE_CLASS != 1:
        return False
    if MIN_ID != 1 or SMALL_RANGE_MAX_ID != (1 << 32) - 1:
        return False
    if BIGINT_RANGE_MIN_ID != SMALL_RANGE_MAX_ID + 1:
        return False
    if MAX_ID != (1 << 64) - 1:
        return False
    if MYSQL_UNSIGNED_BIGINT_MAX != MAX_ID:
        return False
    if SUPPORTED_HEX_LENGTHS != (32,):
        return False
    if MIN_PEPPER_HEX_CHARS != 64 or MAX_PEPPER_HEX_CHARS != 256:
        return False
    if MIN_PEPPER_BYTES != 32 or MAX_PEPPER_BYTES != 128:
        return False
    if DEFAULT_PEPPER_FILE_LOCATION != "~/.sql_hex_id_pepper_file.key":
        return False

    layout = DEFAULT_LAYOUT
    if len(layout.ranges) != 2:
        return False
    if {range_layout.range_class for range_layout in layout.ranges} != {SMALL_RANGE_CLASS, BIGINT_RANGE_CLASS}:
        return False
    for range_layout in layout.ranges:
        if range_layout.range_class > layout.range_mask:
            return False
        if range_layout.id_bits <= 0 or range_layout.tag_bits <= 0:
            return False
        if layout.header_bits + range_layout.id_bits + range_layout.tag_bits != layout.total_bits:
            return False
        if not MIN_ID <= range_layout.min_id <= range_layout.max_id <= range_layout.id_mask:
            return False
    if layout.range_for_class(SMALL_RANGE_CLASS) != SMALL_RANGE_LAYOUT:
        return False
    if layout.range_for_class(BIGINT_RANGE_CLASS) != BIGINT_RANGE_LAYOUT:
        return False
    if layout.range_for_id(1) != SMALL_RANGE_LAYOUT:
        return False
    if layout.range_for_id(SMALL_RANGE_MAX_ID) != SMALL_RANGE_LAYOUT:
        return False
    if layout.range_for_id(BIGINT_RANGE_MIN_ID) != BIGINT_RANGE_LAYOUT:
        return False
    if layout.range_for_id(MAX_ID) != BIGINT_RANGE_LAYOUT:
        return False
    if layout.total_bits % 8 != 0 or layout.total_bits % 2 != 0:
        return False
    if layout.hex_chars != layout.total_bits // 4:
        return False
    if layout.max_id != MAX_ID:
        return False
    if layout.valid_id_count != MAX_ID:
        return False
    if layout.version_mask != RESERVED_VERSION:
        return False
    if layout.label_mask != RESERVED_LABEL:
        return False
    if layout.range_mask != 1:
        return False
    if layout.half_bits > 256:
        return False

    return True


# Readable internal alias for tests and users who introspect internals.
def _constants_are_sane() -> bool:
    """Return True when constants and the fixed layout are valid."""
    return _registry_is_sane()


def layout_for_hex_length(hex_chars: object) -> SqlIdLayout | None:
    """Return the fixed layout for 32 hex chars, or None."""
    if isinstance(hex_chars, bool) or not isinstance(hex_chars, int):
        return None
    return DEFAULT_LAYOUT if hex_chars == HEX_CHARS else None


def _normalize_label_name(name: str) -> str:
    normalized = name.lower()
    if not _LABEL_NAME_RE.fullmatch(normalized):
        raise _InputError("label names must match [a-z][a-z0-9_]{0,31}")
    return normalized


def _validate_label_id(label_id: object, *, allow_zero: bool) -> int:
    if isinstance(label_id, bool) or not isinstance(label_id, int):
        raise _InputError("label must be an int label id or configured label name")
    minimum = NO_LABEL if allow_zero else 1
    if not minimum <= label_id <= MAX_LABEL:
        if allow_zero:
            raise _InputError(f"label id must be {NO_LABEL}..{MAX_LABEL}")
        raise _InputError(f"label id must be 1..{MAX_LABEL}")
    return label_id


def _coerce_label(label: object, *, allow_zero: bool) -> int:
    """Resolve an int label id or configured label name into label bits."""
    if isinstance(label, str):
        normalized = _normalize_label_name(label)
        with _CONFIG_LOCK:
            label_id = _LABELS_BY_NAME.get(normalized)
        if label_id is None:
            raise _InputError(f"unknown SQL ID label: {label!r}")
        return label_id
    return _validate_label_id(label, allow_zero=allow_zero)


def _validated_label_maps(labels: Mapping[str, int]) -> tuple[dict[str, int], dict[int, str]]:
    """Validate label mappings and return normalized forward/reverse maps."""
    if not isinstance(labels, Mapping):
        raise ValueError("labels must be a mapping of name -> label id")

    by_name: dict[str, int] = {}
    by_id: dict[int, str] = {}
    for raw_name, raw_id in tuple(labels.items()):
        if not isinstance(raw_name, str):
            raise ValueError("label names must be strings")
        try:
            name = _normalize_label_name(raw_name)
            label_id = _validate_label_id(raw_id, allow_zero=False)
        except _InputError as exc:
            raise ValueError(str(exc)) from exc
        if name in by_name:
            raise ValueError(f"duplicate label name after normalization: {raw_name!r}")
        if label_id in by_id:
            raise ValueError(f"duplicate label id: {label_id}")
        by_name[name] = label_id
        by_id[label_id] = name

    return by_name, by_id


def _validate_pepper_file_location(value: object) -> str:
    """Validate and normalize a configured pepper-file location."""
    if not isinstance(value, str):
        raise ValueError(f"{PEPPER_FILE_LOCATION_KEY} must be a string path")
    location = value.strip()
    if not location:
        raise ValueError(f"{PEPPER_FILE_LOCATION_KEY} must not be empty")
    if "\x00" in location:
        raise ValueError(f"{PEPPER_FILE_LOCATION_KEY} must not contain NUL bytes")
    return location


def _validated_sql_id_config(config: Mapping[str, object]) -> dict[str, object]:
    """Validate a partial SQL ID config mapping."""
    if not isinstance(config, Mapping):
        raise ValueError("SQL ID config must be a mapping")

    allowed_keys = {PEPPER_FILE_LOCATION_KEY, LABELS_CONFIG_KEY}
    unknown_keys = set(config) - allowed_keys
    if unknown_keys:
        unknown = ", ".join(sorted(str(key) for key in unknown_keys))
        raise ValueError(f"unknown SQL ID config key(s): {unknown}")
    if not any(key in config for key in allowed_keys):
        raise ValueError("SQL ID config must define labels, pepper_file_location, or both")

    normalized: dict[str, object] = {}
    if PEPPER_FILE_LOCATION_KEY in config:
        normalized[PEPPER_FILE_LOCATION_KEY] = _validate_pepper_file_location(config[PEPPER_FILE_LOCATION_KEY])
    if LABELS_CONFIG_KEY in config:
        by_name, _by_id = _validated_label_maps(_labels_from_loaded_data(config[LABELS_CONFIG_KEY]))
        normalized[LABELS_CONFIG_KEY] = by_name
    return normalized


def configure_sql_id(config: Mapping[str, object]) -> None:
    """Configure the local SQL ID pepper-file location and/or label registry.

    The pepper file is key material. The label registry is local metadata only:
    public IDs store numeric label bits, not label names. Missing config keys
    leave the current in-process value unchanged.
    """
    global _PEPPER_FILE_LOCATION, _PEPPER_CACHE, _LABELS_BY_NAME, _LABEL_NAMES_BY_ID

    normalized = _validated_sql_id_config(config)
    with _CONFIG_LOCK:
        if PEPPER_FILE_LOCATION_KEY in normalized:
            _PEPPER_FILE_LOCATION = normalized[PEPPER_FILE_LOCATION_KEY]  # type: ignore[assignment]
            _PEPPER_CACHE = None
            _derive_material.cache_clear()
        if LABELS_CONFIG_KEY in normalized:
            by_name, by_id = _validated_label_maps(normalized[LABELS_CONFIG_KEY])  # type: ignore[arg-type]
            _LABELS_BY_NAME = MappingProxyType(by_name)
            _LABEL_NAMES_BY_ID = MappingProxyType(by_id)


def _reject_duplicate_json_pairs(pairs: list[tuple[object, object]]) -> dict[object, object]:
    """JSON object hook that refuses duplicate keys instead of keeping the last."""
    result: dict[object, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key in JSON config file: {key!r}")
        result[key] = value
    return result


def _yaml_safe_load_no_duplicate_keys(yaml_module: object, text: str) -> object:
    """Load YAML with duplicate mapping keys rejected."""
    safe_loader = yaml_module.SafeLoader  # type: ignore[attr-defined]
    mapping_node = yaml_module.MappingNode  # type: ignore[attr-defined]
    default_mapping_tag = yaml_module.resolver.BaseResolver.DEFAULT_MAPPING_TAG  # type: ignore[attr-defined]
    yaml_load = yaml_module.load  # type: ignore[attr-defined]

    class UniqueKeyLoader(safe_loader):  # type: ignore[valid-type,misc]
        pass

    def construct_mapping(loader: object, node: object, deep: bool = False) -> dict[object, object]:
        if not isinstance(node, mapping_node):
            raise ValueError("config file must contain a YAML mapping")
        mapping: dict[object, object] = {}
        for key_node, value_node in node.value:  # type: ignore[attr-defined]
            key = loader.construct_object(key_node, deep=deep)  # type: ignore[attr-defined]
            if key in mapping:
                raise ValueError(f"duplicate key in YAML config file: {key!r}")
            mapping[key] = loader.construct_object(value_node, deep=deep)  # type: ignore[attr-defined]
        return mapping

    UniqueKeyLoader.add_constructor(default_mapping_tag, construct_mapping)
    return yaml_load(text, Loader=UniqueKeyLoader)


def _labels_from_loaded_data(data: object) -> dict[str, int]:
    """Normalize loaded label data into the public name -> id mapping."""
    if not isinstance(data, Mapping):
        raise ValueError("labels must be a mapping")

    labels: dict[str, int] = {}
    seen_ids: dict[int, str] = {}
    for raw_key, raw_value in data.items():
        if (
            (isinstance(raw_key, str) and raw_key.isdecimal())
            or (isinstance(raw_key, int) and not isinstance(raw_key, bool))
        ) and isinstance(raw_value, str):
            name = raw_value
            label_id = int(raw_key)
        else:
            name = raw_key
            label_id = raw_value
        if not isinstance(name, str):
            raise ValueError("label names must be strings")
        try:
            normalized_name = _normalize_label_name(name)
            validated_id = _validate_label_id(label_id, allow_zero=False)
        except _InputError as exc:
            raise ValueError(str(exc)) from exc
        if normalized_name in labels:
            raise ValueError(f"duplicate label name after normalization: {name!r}")
        if validated_id in seen_ids:
            raise ValueError(f"duplicate label id: {validated_id}")
        labels[normalized_name] = validated_id
        seen_ids[validated_id] = normalized_name
    return labels


def _config_from_loaded_data(data: object) -> dict[str, object]:
    """Normalize loaded JSON/YAML data into a partial SQL ID config mapping."""
    if not isinstance(data, Mapping):
        raise ValueError("config file must contain a mapping")
    return _validated_sql_id_config(data)


def _candidate_config_paths(path: Path) -> tuple[Path, ...]:
    """Return existing same-stem .json/.yaml/.yml config files for comparison."""
    path = path.expanduser()
    suffix = path.suffix.lower()
    if suffix not in {".json", ".yaml", ".yml"}:
        raise ValueError("config file must use .json, .yaml, or .yml")

    candidates = []
    for candidate_suffix in (".json", ".yaml", ".yml"):
        candidate = path.with_suffix(candidate_suffix)
        if candidate.exists():
            candidates.append(candidate)
    if path not in candidates:
        candidates.append(path)
    return tuple(dict.fromkeys(candidates))


def _config_file_cache_key(path: Path) -> Path:
    """Return the same cache key for same-stem .json/.yaml/.yml config files."""
    path = path.expanduser()
    if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
        raise ValueError("config file must use .json, .yaml, or .yml")
    return path.resolve().with_suffix("")


def _load_one_config_file(path: Path) -> dict[str, object]:
    """Load one config file, enforce size, and return a normalized mapping."""
    path = path.expanduser()
    suffix = path.suffix.lower()
    try:
        with path.open("rb") as file_obj:
            raw_data = file_obj.read(_MAX_CONFIG_FILE_BYTES + 1)
        if len(raw_data) > _MAX_CONFIG_FILE_BYTES:
            raise ValueError(f"config file is too large; maximum is {_MAX_CONFIG_FILE_BYTES} bytes")
        try:
            text = raw_data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"config file must be valid UTF-8: {exc}") from exc
        if suffix == ".json":
            data = json.loads(text, object_pairs_hook=_reject_duplicate_json_pairs)
        elif suffix in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-not-found]
            except ImportError as exc:
                raise ValueError("YAML config files require the optional PyYAML package") from exc
            data = _yaml_safe_load_no_duplicate_keys(yaml, text)
        else:
            raise ValueError("config file must use .json, .yaml, or .yml")
    except OSError as exc:
        raise ValueError(f"could not read config file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON config file: {exc}") from exc

    return _config_from_loaded_data(data)


def _load_sql_id_config_files_uncached(config_path: Path) -> dict[str, object]:
    """Load same-stem config files from disk and return a validated mapping."""
    loaded = [(candidate, _load_one_config_file(candidate)) for candidate in _candidate_config_paths(config_path)]
    first_path, first_config = loaded[0]
    for candidate, config in loaded[1:]:
        if config != first_config:
            raise ValueError(f"config files do not match: {first_path} and {candidate}")
    return first_config


def load_sql_id_config_from_file(path: str | os.PathLike[str]) -> None:
    """Configure SQL ID settings from cached or newly loaded config files.

    JSON support uses the Python standard library. YAML support is optional and
    requires PyYAML to be installed. Supported mapping shape:

        {"pepper_file_location": "~/.sql_hex_id_pepper_file.key",
         "labels": {"dry_run": 1, "plan": 2}}

    If same-stem files exist in more than one supported format, all available
    .json, .yaml, and .yml files are loaded and must normalize to the exact
    same SQL ID config. Each file must be no larger than 2000 bytes.

    File content is cached automatically by same-stem path after the first
    successful load. Later calls for the same cache key reuse the cached
    config. Use reload_sql_id_config_from_file() when application logic
    intentionally wants to re-read config files from disk.
    """
    config_path = Path(path).expanduser()
    cache_key = _config_file_cache_key(config_path)
    with _CONFIG_LOCK:
        cached_config = _CONFIG_FILE_CACHE.get(cache_key)
        if cached_config is None:
            loaded_config = _load_sql_id_config_files_uncached(config_path)
            cached_config = MappingProxyType(dict(loaded_config))
            _CONFIG_FILE_CACHE[cache_key] = cached_config
        configure_sql_id(cached_config)


def reload_sql_id_config_from_file(path: str | os.PathLike[str]) -> None:
    """Re-read same-stem config files, refresh the cache, and configure them."""
    config_path = Path(path).expanduser()
    cache_key = _config_file_cache_key(config_path)
    loaded_config = _load_sql_id_config_files_uncached(config_path)
    cached_config = MappingProxyType(dict(loaded_config))
    with _CONFIG_LOCK:
        _CONFIG_FILE_CACHE[cache_key] = cached_config
        configure_sql_id(cached_config)


def clear_sql_id_config() -> None:
    """Reset the pepper-file location, labels, and cached file-loaded config."""
    global _PEPPER_FILE_LOCATION, _PEPPER_CACHE, _LABELS_BY_NAME, _LABEL_NAMES_BY_ID

    with _CONFIG_LOCK:
        _PEPPER_FILE_LOCATION = DEFAULT_PEPPER_FILE_LOCATION
        _PEPPER_CACHE = None
        _LABELS_BY_NAME = MappingProxyType({})
        _LABEL_NAMES_BY_ID = MappingProxyType({})
        _CONFIG_FILE_CACHE.clear()
        _derive_material.cache_clear()


def configured_pepper_file_location() -> str:
    """Return the configured pepper-file location string."""
    with _CONFIG_LOCK:
        return _PEPPER_FILE_LOCATION


def available_labels() -> dict[str, int]:
    """Return a copy of the configured local label-name lookup."""
    with _CONFIG_LOCK:
        return dict(_LABELS_BY_NAME)


def _label_name_for_id(label_id: int) -> str | None:
    with _CONFIG_LOCK:
        return _LABEL_NAMES_BY_ID.get(label_id)


def _password_bytes() -> bytes:
    """Return configured password bytes or raise an internal config error."""
    password = os.environ.get(ENV_PASSWORD_NAME)
    if not isinstance(password, str):
        raise _ConfigError("bad_config", f"{ENV_PASSWORD_NAME} is required")

    password_bytes = password.encode("utf-8")
    if len(password_bytes) < MIN_PASSWORD_BYTES:
        raise _ConfigError("bad_config", f"{ENV_PASSWORD_NAME} must be at least {MIN_PASSWORD_BYTES} bytes")
    if len(set(password_bytes)) < MIN_PASSWORD_UNIQUE_BYTES:
        raise _ConfigError("bad_config", f"{ENV_PASSWORD_NAME} has too little byte diversity")
    return password_bytes


def _configured_pepper_path() -> Path:
    with _CONFIG_LOCK:
        location = _PEPPER_FILE_LOCATION
    return Path(location).expanduser()


def _validate_pepper_permissions(path: Path, file_stat: os.stat_result) -> None:
    """Reject pepper files with permissions that expose or mutate key material."""
    if not stat.S_ISREG(file_stat.st_mode):
        raise _ConfigError("bad_pepper_file", f"pepper path is not a regular file: {path}")

    if os.name != "posix":
        return

    mode = stat.S_IMODE(file_stat.st_mode)
    disallowed = stat.S_IXUSR | stat.S_IWGRP | stat.S_IXGRP | stat.S_IRWXO
    if mode & disallowed:
        raise _ConfigError(
            "bad_pepper_permissions",
            "pepper file permissions must not allow execution, group write, or any other-user access",
        )
    if not mode & (stat.S_IRUSR | stat.S_IRGRP):
        raise _ConfigError("bad_pepper_permissions", "pepper file must be readable by owner or group")


def _open_pepper_fd(path: Path) -> int:
    """Open the pepper file without following symlinks on POSIX platforms."""
    flags = os.O_RDONLY
    if os.name == "posix":
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            if stat.S_ISLNK(path.lstat().st_mode):
                raise _ConfigError("bad_pepper_file", f"pepper path must not be a symlink: {path}")
        except FileNotFoundError as exc:
            raise _ConfigError("missing_pepper_file", f"pepper file does not exist: {path}") from exc
        except _ConfigError:
            raise
        except OSError as exc:
            raise _ConfigError("unreadable_pepper_file", f"could not stat pepper file: {exc}") from exc

    try:
        return os.open(path, flags)
    except FileNotFoundError as exc:
        raise _ConfigError("missing_pepper_file", f"pepper file does not exist: {path}") from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise _ConfigError("bad_pepper_file", f"pepper path must not be a symlink: {path}") from exc
        raise _ConfigError("unreadable_pepper_file", f"could not open pepper file: {exc}") from exc


def _read_pepper_bytes_from_path(path: Path) -> bytes:
    """Read and validate pepper bytes from one already-selected path."""
    fd = _open_pepper_fd(path)
    try:
        try:
            file_stat = os.fstat(fd)
        except OSError as exc:
            raise _ConfigError("unreadable_pepper_file", f"could not stat pepper file: {exc}") from exc
        _validate_pepper_permissions(path, file_stat)
        if file_stat.st_size > _MAX_PEPPER_FILE_BYTES:
            raise _ConfigError("pepper_too_long", f"pepper file must be at most {_MAX_PEPPER_FILE_BYTES} bytes")

        try:
            raw_data = os.read(fd, _MAX_PEPPER_FILE_BYTES + 1)
        except OSError as exc:
            raise _ConfigError("unreadable_pepper_file", f"could not read pepper file: {exc}") from exc
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    if len(raw_data) > _MAX_PEPPER_FILE_BYTES:
        raise _ConfigError("pepper_too_long", f"pepper file must be at most {_MAX_PEPPER_FILE_BYTES} bytes")
    try:
        text = raw_data.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise _ConfigError("invalid_pepper_hex", f"pepper file must contain ASCII hex: {exc}") from exc

    if len(text) < MIN_PEPPER_HEX_CHARS:
        raise _ConfigError("pepper_too_short", f"pepper hex must be at least {MIN_PEPPER_HEX_CHARS} characters")
    if len(text) > MAX_PEPPER_HEX_CHARS:
        raise _ConfigError("pepper_too_long", f"pepper hex must be at most {MAX_PEPPER_HEX_CHARS} characters")
    if len(text) % 2:
        raise _ConfigError("invalid_pepper_hex", "pepper hex must have an even number of characters")
    if not _HEX_CHARS_RE.fullmatch(text):
        raise _ConfigError("invalid_pepper_hex", "pepper file must contain only hex characters")

    pepper = bytes.fromhex(text)
    if not MIN_PEPPER_BYTES <= len(pepper) <= MAX_PEPPER_BYTES:
        raise _ConfigError("bad_pepper_file", f"pepper must decode to {MIN_PEPPER_BYTES}..{MAX_PEPPER_BYTES} bytes")
    if len(set(pepper)) < MIN_PEPPER_UNIQUE_BYTES:
        raise _ConfigError("low_diversity_pepper", "pepper has too little byte diversity")
    return pepper


def _pepper_bytes() -> bytes:
    """Return cached pepper bytes for the configured disk file."""
    global _PEPPER_CACHE

    with _CONFIG_LOCK:
        path = _configured_pepper_path()
        cache_key = path.resolve()
        if _PEPPER_CACHE is not None and _PEPPER_CACHE[0] == cache_key:
            return _PEPPER_CACHE[1]

        pepper = _read_pepper_bytes_from_path(path)
        _PEPPER_CACHE = (cache_key, pepper)
        return pepper


def reload_sql_id_pepper() -> None:
    """Explicitly re-read and cache the currently configured pepper file."""
    global _PEPPER_CACHE

    with _CONFIG_LOCK:
        path = _configured_pepper_path()
        cache_key = path.resolve()
        pepper = _read_pepper_bytes_from_path(path)
        _PEPPER_CACHE = (cache_key, pepper)
        _derive_material.cache_clear()


@lru_cache(maxsize=32)
def _derive_material(password_bytes: bytes, pepper_bytes: bytes, layout: SqlIdLayout) -> tuple[tuple[bytes, ...], bytes]:
    """Derive layout-specific Feistel round keys and validation-tag key."""
    root_key = hmac.new(
        password_bytes,
        (
            b"xctx-sql-id-root-v4:"
            + layout.domain_label()
            + b":salt:"
            + _DOMAIN_SALT
            + b":pepper:"
            + pepper_bytes
        ),
        hashlib.sha256,
    ).digest()
    seed = hmac.new(
        root_key,
        b":xctx-sql-id-v4-feistel-and-tag-seed:" + layout.domain_label(),
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
        (
            b":keyed-validation-tags:"
            + layout.min_tag_bits.to_bytes(2, "big")
            + b":"
            + layout.max_tag_bits.to_bytes(2, "big")
        ),
        hashlib.sha256,
    ).digest()
    return outer_round_keys, tag_key


def _key_material(layout: SqlIdLayout = DEFAULT_LAYOUT) -> tuple[tuple[bytes, ...], bytes]:
    """Return configured key material for the fixed layout or raise an error."""
    if layout != DEFAULT_LAYOUT or not _registry_is_sane():
        raise _ConfigError("bad_config", "invalid sql_id_library layout")
    return _derive_material(_password_bytes(), _pepper_bytes(), layout)


def is_configured() -> bool:
    """Return whether the module has enough configuration to encode/decode IDs."""
    try:
        _key_material(DEFAULT_LAYOUT)
        return True
    except Exception:  # noqa: BLE001 - configuration probe must not crash callers
        return False


def _coerce_id(value: object, layout: SqlIdLayout = DEFAULT_LAYOUT) -> int:
    """Strictly coerce caller input into an integer SQL ID."""
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
            raise _InputError("id string too long for uint64 range")
        id_value = int(value)
    else:
        raise _InputError("id must be an int or decimal digit string")

    if not MIN_ID <= id_value <= layout.max_id:
        raise _InputError(f"id is outside range 1..{layout.max_id}")
    return id_value


def _round_function(right: int, key: bytes, layout: SqlIdLayout) -> int:
    """Return a deterministic half-width Feistel round output."""
    digest = hmac.new(key, right.to_bytes(layout.half_bytes, "big"), hashlib.sha256).digest()
    return int.from_bytes(digest[: layout.half_bytes], "big") & layout.half_mask


def _feistel_encrypt(value: int, round_keys: tuple[bytes, ...], layout: SqlIdLayout = DEFAULT_LAYOUT) -> int:
    """Apply the secret-derived Feistel permutation to one layout-width integer."""
    if not 0 <= value <= layout.value_mask:
        raise ValueError("value is outside layout range")

    left = (value >> layout.half_bits) & layout.half_mask
    right = value & layout.half_mask

    for key in round_keys:
        left, right = right, (left ^ _round_function(right, key, layout)) & layout.half_mask

    return ((left << layout.half_bits) | right) & layout.value_mask


def _feistel_decrypt(value: int, round_keys: tuple[bytes, ...], layout: SqlIdLayout = DEFAULT_LAYOUT) -> int:
    """Invert the secret-derived Feistel permutation for one layout-width integer."""
    if not 0 <= value <= layout.value_mask:
        raise ValueError("value is outside layout range")

    left = (value >> layout.half_bits) & layout.half_mask
    right = value & layout.half_mask

    for key in reversed(round_keys):
        left, right = (right ^ _round_function(left, key, layout)) & layout.half_mask, left

    return ((left << layout.half_bits) | right) & layout.value_mask


def _tag(
    version: int,
    label_id: int,
    range_class: int,
    id_value: int,
    tag_key: bytes,
    layout: SqlIdLayout = DEFAULT_LAYOUT,
) -> int:
    """Return a keyed validation tag for version, label, range, and SQL ID."""
    if not 0 <= version <= layout.version_mask:
        raise ValueError("version out of range")
    if not 0 <= label_id <= layout.label_mask:
        raise ValueError("label out of range")
    if not 0 <= range_class <= layout.range_mask:
        raise ValueError("range class out of range")
    range_layout = layout.range_for_class(range_class)
    if not 0 <= id_value <= range_layout.id_mask:
        raise ValueError("id value out of range for range class")

    message = (
        layout.domain_label()
        + b":version:"
        + version.to_bytes(1, "big")
        + b":label:"
        + label_id.to_bytes(1, "big")
        + b":range:"
        + range_class.to_bytes(1, "big")
        + b":id:"
        + id_value.to_bytes(range_layout.id_bytes, "big")
    )
    digest = hmac.new(tag_key, message, hashlib.sha256).digest()
    return int.from_bytes(digest[: range_layout.tag_bytes], "big") & range_layout.tag_mask


def _tags_equal(left: int, right: int, range_layout: SqlIdRangeLayout) -> bool:
    """Compare compact integer tags without data-dependent short-circuiting."""
    return hmac.compare_digest(
        (left & range_layout.tag_mask).to_bytes(range_layout.tag_bytes, "big"),
        (right & range_layout.tag_mask).to_bytes(range_layout.tag_bytes, "big"),
    )


def _pack_plain_fields(
    version: int,
    label_id: int,
    range_class: int,
    id_value: int,
    tag: int,
    layout: SqlIdLayout = DEFAULT_LAYOUT,
) -> int:
    """Pack already-validated field-width values into one plaintext integer."""
    if not 0 <= version <= layout.version_mask:
        raise ValueError("version out of range")
    if not 0 <= label_id <= layout.label_mask:
        raise ValueError("label out of range")
    if not 0 <= range_class <= layout.range_mask:
        raise ValueError("range class out of range")
    range_layout = layout.range_for_class(range_class)
    if not 0 <= id_value <= range_layout.id_mask:
        raise ValueError("id value out of range for range class")
    if not 0 <= tag <= range_layout.tag_mask:
        raise ValueError("tag out of range for range class")

    return (
        ((version & layout.version_mask) << (layout.total_bits - layout.version_bits))
        | ((label_id & layout.label_mask) << (layout.total_bits - layout.version_bits - layout.label_bits))
        | ((range_class & layout.range_mask) << (layout.total_bits - layout.header_bits))
        | ((id_value & range_layout.id_mask) << range_layout.tag_bits)
        | tag
    ) & layout.value_mask


def _pack_plain(
    version: int,
    label_id: int,
    id_value: int,
    tag_key: bytes,
    layout: SqlIdLayout = DEFAULT_LAYOUT,
    *,
    range_class: int | None = None,
) -> int:
    """Pack version, label, canonical SQL ID range, ID, and keyed tag into 128 bits."""
    if not 0 <= version <= layout.version_mask:
        raise ValueError("version out of range")
    if not 0 <= label_id <= layout.label_mask:
        raise ValueError("label out of range")
    if range_class is None:
        range_layout = layout.range_for_id(id_value)
    else:
        range_layout = layout.range_for_class(range_class)
        if not range_layout.min_id <= id_value <= range_layout.max_id:
            raise ValueError("id value is outside the canonical range class")

    tag = _tag(version, label_id, range_layout.range_class, id_value, tag_key, layout)
    return _pack_plain_fields(version, label_id, range_layout.range_class, id_value, tag, layout)


def _unpack_plain(value: int, layout: SqlIdLayout = DEFAULT_LAYOUT) -> tuple[int, int, int, int, int]:
    """Unpack a plaintext value into version, label, range class, SQL ID, and tag."""
    if not 0 <= value <= layout.value_mask:
        raise ValueError("value is outside layout range")

    version = (value >> (layout.total_bits - layout.version_bits)) & layout.version_mask
    label_id = (value >> (layout.total_bits - layout.version_bits - layout.label_bits)) & layout.label_mask
    range_class = (value >> (layout.total_bits - layout.header_bits)) & layout.range_mask
    range_layout = layout.range_for_class(range_class)
    id_value = (value >> range_layout.tag_bits) & range_layout.id_mask
    tag = value & range_layout.tag_mask
    return version, label_id, range_class, id_value, tag


def _encode_with_label(id_value: object, label_id: int) -> str | None:
    try:
        sql_id = _coerce_id(id_value, DEFAULT_LAYOUT)
        round_keys, tag_key = _key_material(DEFAULT_LAYOUT)
        plain = _pack_plain(ISSUE_VERSION, label_id, sql_id, tag_key, DEFAULT_LAYOUT)
        encrypted = _feistel_encrypt(plain, round_keys, DEFAULT_LAYOUT)
        return f"{encrypted:0{HEX_CHARS}x}"
    except Exception:  # noqa: BLE001 - public convenience API returns None
        return None


def id_to_hex(value: object) -> str | None:
    """Return an unlabeled lowercase public hex ID, or None on any failure."""
    return _encode_with_label(value, NO_LABEL)


def id_to_hex_label(value: object, label: object) -> str | None:
    """Return a labeled lowercase public hex ID for a label resolving to 1..30."""
    try:
        label_id = _coerce_label(label, allow_zero=False)
    except Exception:
        return None
    return _encode_with_label(value, label_id)


def sql_generate_id(id_required: object) -> str | None:
    """Alias for id_to_hex(): return unlabeled hex from an id."""
    return id_to_hex(id_required)


def sql_generate_id_label(id_required: object, label: object) -> str | None:
    """Alias for id_to_hex_label(): return labeled hex from an id."""
    return id_to_hex_label(id_required, label)


def _validation_error(
    code: str,
    message: str,
    *,
    public_hex: str | None = None,
    layout: SqlIdLayout | None = None,
    version: int | None = None,
    label_id: int | None = None,
    range_class: int | None = None,
    tag_bits: int | None = None,
) -> SqlIdValidation:
    return SqlIdValidation(
        ok=False,
        public_hex=public_hex,
        label_id=label_id,
        label=_label_name_for_id(label_id) if label_id is not None else None,
        range_class=range_class,
        tag_bits=tag_bits,
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


def _decode_public_hex(value: object, *, expected_label: int | None) -> SqlIdValidation:
    """Decode and validate a public hex ID, optionally requiring one exact label."""
    if not isinstance(value, str):
        return _validation_error("not_string", "public id must be a hex string")

    if len(value) != HEX_CHARS:
        return _validation_error(
            "unsupported_length",
            f"public id length must be exactly {HEX_CHARS} hex characters",
            public_hex=_public_hex_for_length_error(value),
        )

    if not _HEX_CHARS_RE.fullmatch(value):
        return _validation_error("invalid_hex", "public id must contain only hex characters", public_hex=value)

    public_hex = value.lower()

    try:
        round_keys, tag_key = _key_material(DEFAULT_LAYOUT)
        encrypted = int(public_hex, 16)
        plain = _feistel_decrypt(encrypted, round_keys, DEFAULT_LAYOUT)
        version, label_id, range_class, id_value, supplied_tag = _unpack_plain(plain, DEFAULT_LAYOUT)
        range_layout = DEFAULT_LAYOUT.range_for_class(range_class)

        expected_tag = _tag(version, label_id, range_class, id_value, tag_key, DEFAULT_LAYOUT)
        if not _tags_equal(supplied_tag, expected_tag, range_layout):
            raise _ValidationFailure("tag_mismatch", "public id validation tag does not match")
        if version not in ACTIVE_DECODE_VERSIONS:
            raise _ValidationFailure("unsupported_version", "public id uses an inactive version")
        if label_id == RESERVED_LABEL:
            raise _ValidationFailure("reserved_label", "public id uses a reserved label")
        if expected_label is not None and label_id != expected_label:
            raise _ValidationFailure("label_mismatch", "public id label does not match the expected label")
        if not range_layout.min_id <= id_value <= range_layout.max_id:
            raise _ValidationFailure("id_out_of_range", "decoded id is outside the canonical range")

        return SqlIdValidation(
            ok=True,
            id=id_value,
            public_hex=public_hex,
            label_id=label_id,
            label=_label_name_for_id(label_id),
            range_class=range_class,
            tag_bits=range_layout.tag_bits,
            version=version,
            layout=DEFAULT_LAYOUT,
        )
    except _ConfigError as exc:
        return _validation_error(exc.code, exc.message, public_hex=public_hex, layout=DEFAULT_LAYOUT)
    except _ValidationFailure as exc:
        return _validation_error(
            exc.code,
            exc.message,
            public_hex=public_hex,
            layout=DEFAULT_LAYOUT,
            version=locals().get("version"),
            label_id=locals().get("label_id"),
            range_class=locals().get("range_class"),
            tag_bits=locals().get("range_layout").tag_bits if "range_layout" in locals() else None,
        )
    except Exception as exc:  # noqa: BLE001 - validation returns a real error, not an exception
        return _validation_error("internal_error", f"internal validation failure: {exc}", public_hex=public_hex, layout=DEFAULT_LAYOUT)


def validate_hex(value: object) -> SqlIdValidation:
    """Validate an unlabeled public ID and return structured detail."""
    return _decode_public_hex(value, expected_label=NO_LABEL)


def validate_hex_label(value: object, label: object) -> SqlIdValidation:
    """Validate a labeled public ID against one exact expected label."""
    try:
        expected_label = _coerce_label(label, allow_zero=False)
    except _InputError as exc:
        return _validation_error("invalid_label", str(exc))
    return _decode_public_hex(value, expected_label=expected_label)


def inspect_hex(value: object) -> SqlIdValidation:
    """Inspect any valid non-reserved label. Do not use as route enforcement."""
    return _decode_public_hex(value, expected_label=None)


def sql_validate_id(value: object) -> SqlIdValidation:
    """Alias for validate_hex(): validate an unlabeled public ID."""
    return validate_hex(value)


def sql_validate_id_label(value: object, label: object) -> SqlIdValidation:
    """Alias for validate_hex_label(): validate a labeled public ID."""
    return validate_hex_label(value, label)


def hex_to_id(value: object) -> int | None:
    """Return the integer for an unlabeled public ID, or None on any failure."""
    result = validate_hex(value)
    return result.id if result.ok else None


def hex_to_id_label(value: object, label: object) -> int | None:
    """Return the integer for a public ID with the exact expected label."""
    result = validate_hex_label(value, label)
    return result.id if result.ok else None


def sql_decode_id(value: object) -> int | None:
    """Alias for hex_to_id(): return an id from unlabeled hex."""
    return hex_to_id(value)


def sql_decode_id_label(value: object, label: object) -> int | None:
    """Alias for hex_to_id_label(): return an id from hex with the expected label."""
    return hex_to_id_label(value, label)


def hex_to_parts(value: object) -> tuple[int, str | None, int, int] | None:
    """Return (label_id, label_name, version, integer_id) for any valid non-reserved label."""
    result = inspect_hex(value)
    if not result.ok or result.id is None or result.label_id is None or result.version is None:
        return None
    return result.label_id, result.label, result.version, result.id
