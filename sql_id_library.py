"""Reversible 16-hex-character public IDs for SQL integer keys.

This module turns a positive SQL integer ID into a deterministic public hex ID,
and turns a valid public hex ID back into the original integer. The public ID is
always 16 lowercase hex characters:

    3 version bits + 5 label bits + 32 id bits + 24 keyed tag bits = 64 bits

Label ``0`` is the ordinary unlabeled mode used by ``id_to_hex()`` and
``hex_to_id()``. Labels ``1..30`` are typed/table/bucket labels used only by the
explicit labeled API. Label ``31`` is reserved.

Plain layout before the Feistel permutation:

    [ version ][ label ][ zero-based SQL id index ][ keyed validation tag ]

The keyed validation tag covers the scheme, bit layout, version, label, and ID
index. A valid labeled ID cannot be reinterpreted as unlabeled, and a valid ID
for one label cannot be decoded by asking for another label.

Security model:

    This is a deterministic public-handle layer for internal SQL integer IDs. It
    hides sequential IDs and rejects almost all random/tampered inputs. It is not
    a bearer token, authentication system, authorization system, or proof of
    permission. Always check decoded IDs against normal application permissions
    and business rules.

Strict decoder probability:

    The integer-returning APIs always check one exact expected label:

        hex_to_id(public_hex)                 expects label 0
        hex_to_id_label(public_hex, label)    expects labels 1..30

    For one expected label, random-valid probability is:

        (2**32 - 1) / 2**64, just under 2**-32

Generic inspection:

    ``inspect_hex()`` and ``hex_to_parts()`` are diagnostic helpers. They accept
    any valid non-reserved label, so they are intentionally not the enforcement
    API for typed routes.

Secret configuration:

    Set XCTX_ID_PASSWORD to at least 32 UTF-8 bytes of secret. Recommended:

        python -c "import secrets; print(secrets.token_hex(32))"

    Store the printed 64-hex-character value in XCTX_ID_PASSWORD. The fixed
    domain salt below is not secret; the environment value is the key.

Operational hardening:

    A real deployment should count bad public IDs as suspicious. A strong policy
    such as 10 bad IDs per session/IP/account bucket per 30 minutes caps online
    guessing to:

        10 * 2 * 24 * 365 = 175_200 guesses/year/bucket

    For strict expected-label decoding, random-valid odds are just under 2**-32,
    so the worst-case expected time to hit any syntactically valid public ID is:

        2**32 / 175_200 ~= 24_515 years/bucket

    This rate-limit policy raises the practical online attack cost. It does not
    turn these IDs into possession-grants-access tokens. For reset links,
    magic-login links, invite tokens, download grants, API keys, sessions, or any
    bearer-token use case, use independent random tokens of at least 128 bits.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
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

SCHEME_REVISION: Final[int] = 2
VERSION_BITS: Final[int] = 3
LABEL_BITS: Final[int] = 5
ID_BITS: Final[int] = 32
TAG_BITS: Final[int] = 24
TOTAL_BITS: Final[int] = 64
HEX_CHARS: Final[int] = 16

ISSUE_VERSION: Final[int] = 1
NO_LABEL: Final[int] = 0
RESERVED_VERSION: Final[int] = (1 << VERSION_BITS) - 1
RESERVED_LABEL: Final[int] = (1 << LABEL_BITS) - 1
MAX_LABEL: Final[int] = RESERVED_LABEL - 1
MIN_ID: Final[int] = 1
MAX_ID: Final[int] = (1 << ID_BITS) - 1
MYSQL_UNSIGNED_INT_MAX: Final[int] = MAX_ID
ROUNDS: Final[int] = 16

ACTIVE_DECODE_VERSIONS: Final[frozenset[int]] = frozenset({ISSUE_VERSION})
SUPPORTED_HEX_LENGTHS: Final[tuple[int, ...]] = (HEX_CHARS,)

# Fixed 32-byte domain-separation salt. This is not secret; the environment
# secret is the secret. Changing this salt intentionally creates a new scheme.
DOMAIN_SALT_HEX: Final[str] = "0b91b4e8fd74bcb256a19d188c83470a7b75a4897babb252e54b6eb8f8bb392d"
_DOMAIN_SALT: Final[bytes] = bytes.fromhex(DOMAIN_SALT_HEX)

_DECIMAL_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9]+$")
_HEX_CHARS_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]+$")
_LABEL_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


@dataclass(frozen=True)
class SqlIdLayout:
    """The fixed 64-bit public-ID layout."""

    version_bits: int
    label_bits: int
    id_bits: int
    tag_bits: int
    total_bits: int
    hex_chars: int

    @property
    def bytes(self) -> int:
        return self.total_bits // 8

    @property
    def id_states(self) -> int:
        return 1 << self.id_bits

    @property
    def max_id(self) -> int:
        # ID 0 is invalid and SQL IDs are represented as zero-based indexes.
        # Rejecting the raw all-ones id-index state makes max == 2**32 - 1.
        return (1 << self.id_bits) - 1

    @property
    def version_mask(self) -> int:
        return (1 << self.version_bits) - 1

    @property
    def label_mask(self) -> int:
        return (1 << self.label_bits) - 1

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
    def random_valid_probability_for_expected_label(self) -> float:
        return self.max_id / float(1 << self.total_bits)

    @property
    def random_valid_probability_for_any_label(self) -> float:
        return ((MAX_LABEL + 1) * self.max_id) / float(1 << self.total_bits)

    def domain_label(self) -> bytes:
        """Return canonical bytes for key-domain separation."""
        return (
            f"scheme={SCHEME_REVISION};version_bits={self.version_bits};"
            f"label_bits={self.label_bits};id_bits={self.id_bits};"
            f"tag_bits={self.tag_bits};total_bits={self.total_bits};"
            f"hex_chars={self.hex_chars};issue_version={ISSUE_VERSION};"
            f"no_label={NO_LABEL};max_label={MAX_LABEL};"
            f"reserved_label={RESERVED_LABEL};reserved_version={RESERVED_VERSION}"
        ).encode("ascii")


@dataclass(frozen=True)
class SqlIdValidation:
    """Structured validation result returned by validate/inspect helpers."""

    ok: bool
    id: int | None = None
    public_hex: str | None = None
    label_id: int | None = None
    label: str | None = None
    version: int | None = None
    layout: SqlIdLayout | None = None
    error_code: str | None = None
    error: str | None = None


DEFAULT_LAYOUT: Final[SqlIdLayout] = SqlIdLayout(
    version_bits=VERSION_BITS,
    label_bits=LABEL_BITS,
    id_bits=ID_BITS,
    tag_bits=TAG_BITS,
    total_bits=TOTAL_BITS,
    hex_chars=HEX_CHARS,
)
LAYOUT: Final[SqlIdLayout] = DEFAULT_LAYOUT
MAX_PUBLIC_HEX_CHARS: Final[int] = HEX_CHARS

# Hard caps for untrusted string inputs. Public IDs are exactly 16 hex chars,
# and uint32 decimal IDs need 10 digits; 32 leaves room for leading-zero padding.
_MAX_PUBLIC_HEX_CHARS: Final[int] = HEX_CHARS
_MAX_DECIMAL_ID_STRING_CHARS: Final[int] = 32
_MAX_LABEL_FILE_BYTES: Final[int] = 2000

_LABEL_LOCK = RLock()
_LABELS_BY_NAME: Mapping[str, int] = MappingProxyType({})
_LABEL_NAMES_BY_ID: Mapping[int, str] = MappingProxyType({})
_LABEL_FILE_CACHE: dict[Path, Mapping[str, int]] = {}

__all__ = [
    "ACTIVE_DECODE_VERSIONS",
    "DEFAULT_LAYOUT",
    "DOMAIN_SALT_HEX",
    "ENV_PASSWORD_NAME",
    "HEX_CHARS",
    "ID_BITS",
    "ISSUE_VERSION",
    "LABEL_BITS",
    "LAYOUT",
    "MAX_ID",
    "MAX_LABEL",
    "MIN_ID",
    "MIN_PASSWORD_BYTES",
    "MYSQL_UNSIGNED_INT_MAX",
    "NO_LABEL",
    "RESERVED_LABEL",
    "RESERVED_VERSION",
    "ROUNDS",
    "SCHEME_REVISION",
    "SUPPORTED_HEX_LENGTHS",
    "SqlIdLayout",
    "SqlIdValidation",
    "TAG_BITS",
    "TOTAL_BITS",
    "VERSION_BITS",
    "available_labels",
    "clear_sql_id_labels",
    "configure_sql_id_labels",
    "hex_to_id",
    "hex_to_id_label",
    "hex_to_parts",
    "id_to_hex",
    "id_to_hex_label",
    "inspect_hex",
    "is_configured",
    "layout_for_hex_length",
    "load_sql_id_labels_from_file",
    "re_load_sql_id_labels_from_file",
    "reload_sql_id_labels_from_file",
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
    if VERSION_BITS != 3 or LABEL_BITS != 5 or ID_BITS != 32 or TAG_BITS != 24:
        return False
    if TOTAL_BITS != VERSION_BITS + LABEL_BITS + ID_BITS + TAG_BITS:
        return False
    if TOTAL_BITS != 64 or HEX_CHARS != 16:
        return False
    if DEFAULT_LAYOUT.total_bits != TOTAL_BITS or DEFAULT_LAYOUT.hex_chars != HEX_CHARS:
        return False
    if DEFAULT_LAYOUT.bytes != 8 or DEFAULT_LAYOUT.half_bits != 32:
        return False
    if not 1 <= ISSUE_VERSION < RESERVED_VERSION:
        return False
    if ACTIVE_DECODE_VERSIONS != frozenset({ISSUE_VERSION}):
        return False
    if NO_LABEL != 0 or RESERVED_LABEL != 31 or MAX_LABEL != 30:
        return False
    if MIN_ID != 1 or MAX_ID != (1 << 32) - 1:
        return False
    if MYSQL_UNSIGNED_INT_MAX != MAX_ID:
        return False
    if SUPPORTED_HEX_LENGTHS != (16,):
        return False

    layout = DEFAULT_LAYOUT
    if layout.version_bits + layout.label_bits + layout.id_bits + layout.tag_bits != layout.total_bits:
        return False
    if layout.total_bits % 8 != 0 or layout.total_bits % 2 != 0:
        return False
    if layout.hex_chars != layout.total_bits // 4:
        return False
    if layout.max_id != MAX_ID:
        return False
    if layout.version_mask != RESERVED_VERSION:
        return False
    if layout.label_mask != RESERVED_LABEL:
        return False
    if layout.half_bits > 256:
        return False

    return True


# Backwards-readable name for tests and users who introspect internals.
def _constants_are_sane() -> bool:
    """Return True when constants and the fixed layout are valid."""
    return _registry_is_sane()


def layout_for_hex_length(hex_chars: object) -> SqlIdLayout | None:
    """Return the fixed layout for 16 hex chars, or None."""
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
        with _LABEL_LOCK:
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


def configure_sql_id_labels(labels: Mapping[str, int]) -> None:
    """Configure local names for label IDs 1..30.

    This lookup is local metadata only. The public ID stores the numeric label
    bits, not the label name. Configure labels once during application startup.
    """
    global _LABELS_BY_NAME, _LABEL_NAMES_BY_ID

    by_name, by_id = _validated_label_maps(labels)
    with _LABEL_LOCK:
        _LABELS_BY_NAME = MappingProxyType(by_name)
        _LABEL_NAMES_BY_ID = MappingProxyType(by_id)


def _reject_duplicate_json_pairs(pairs: list[tuple[object, object]]) -> dict[object, object]:
    """JSON object hook that refuses duplicate keys instead of keeping the last."""
    result: dict[object, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key in JSON label file: {key!r}")
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
            raise ValueError("label file must contain a YAML mapping")
        mapping: dict[object, object] = {}
        for key_node, value_node in node.value:  # type: ignore[attr-defined]
            key = loader.construct_object(key_node, deep=deep)  # type: ignore[attr-defined]
            if key in mapping:
                raise ValueError(f"duplicate key in YAML label file: {key!r}")
            mapping[key] = loader.construct_object(value_node, deep=deep)  # type: ignore[attr-defined]
        return mapping

    UniqueKeyLoader.add_constructor(default_mapping_tag, construct_mapping)
    return yaml_load(text, Loader=UniqueKeyLoader)


def _labels_from_loaded_data(data: object) -> dict[str, int]:
    """Normalize loaded label data into the public name -> id mapping."""
    if not isinstance(data, Mapping):
        raise ValueError("label file must contain a mapping")

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
            raise ValueError("label file names must be strings")
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


def _candidate_label_paths(path: Path) -> tuple[Path, ...]:
    """Return existing same-stem JSON/YAML label files for comparison."""
    suffix = path.suffix.lower()
    if suffix not in {".json", ".yaml", ".yml"}:
        raise ValueError("label file must use .json, .yaml, or .yml")

    candidates = []
    for candidate_suffix in (".json", ".yaml", ".yml"):
        candidate = path.with_suffix(candidate_suffix)
        if candidate.exists():
            candidates.append(candidate)
    if path not in candidates:
        candidates.append(path)
    return tuple(dict.fromkeys(candidates))


def _label_file_cache_key(path: Path) -> Path:
    """Return the same cache key for same-stem JSON/YAML label files."""
    if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
        raise ValueError("label file must use .json, .yaml, or .yml")
    return path.expanduser().resolve().with_suffix("")


def _load_one_label_file(path: Path) -> dict[str, int]:
    """Load one label file, enforce size, and return a normalized mapping."""
    suffix = path.suffix.lower()
    try:
        with path.open("rb") as file_obj:
            raw_data = file_obj.read(_MAX_LABEL_FILE_BYTES + 1)
        if len(raw_data) > _MAX_LABEL_FILE_BYTES:
            raise ValueError(f"label file is too large; maximum is {_MAX_LABEL_FILE_BYTES} bytes")
        try:
            text = raw_data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"label file must be valid UTF-8: {exc}") from exc
        if suffix == ".json":
            data = json.loads(text, object_pairs_hook=_reject_duplicate_json_pairs)
        elif suffix in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-not-found]
            except ImportError as exc:
                raise ValueError("YAML label files require the optional PyYAML package") from exc
            data = _yaml_safe_load_no_duplicate_keys(yaml, text)
        else:
            raise ValueError("label file must use .json, .yaml, or .yml")
    except OSError as exc:
        raise ValueError(f"could not read label file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON label file: {exc}") from exc

    by_name, _by_id = _validated_label_maps(_labels_from_loaded_data(data))
    return by_name


def _load_sql_id_label_files_uncached(label_path: Path) -> dict[str, int]:
    """Load same-stem label files from disk and return a validated mapping."""
    loaded = [(candidate, _load_one_label_file(candidate)) for candidate in _candidate_label_paths(label_path)]
    first_path, first_labels = loaded[0]
    for candidate, labels in loaded[1:]:
        if labels != first_labels:
            raise ValueError(f"label files do not match: {first_path} and {candidate}")
    return first_labels


def load_sql_id_labels_from_file(path: str | os.PathLike[str]) -> None:
    """Load cached label names from JSON/YAML files and configure them.

    JSON support uses the Python standard library. YAML support is optional and
    requires PyYAML to be installed. Supported mapping shapes are:

        {"dry_run": 1, "plan": 2}
        {"1": "dry_run", "2": "plan"}

    If same-stem JSON and YAML files both exist, all available files are loaded
    and must normalize to the same label registry. Each file must be no larger
    than 2000 bytes.

    File content is cached by same-stem path after the first successful load.
    Use reload_sql_id_labels_from_file() when application logic intentionally
    wants to re-read label files from disk.
    """
    label_path = Path(path)
    cache_key = _label_file_cache_key(label_path)
    with _LABEL_LOCK:
        cached_labels = _LABEL_FILE_CACHE.get(cache_key)
        if cached_labels is None:
            loaded_labels = _load_sql_id_label_files_uncached(label_path)
            cached_labels = MappingProxyType(dict(loaded_labels))
            _LABEL_FILE_CACHE[cache_key] = cached_labels
        configure_sql_id_labels(cached_labels)


def reload_sql_id_labels_from_file(path: str | os.PathLike[str]) -> None:
    """Re-read label names from disk, refresh the cache, and configure them."""
    label_path = Path(path)
    cache_key = _label_file_cache_key(label_path)
    loaded_labels = _load_sql_id_label_files_uncached(label_path)
    cached_labels = MappingProxyType(dict(loaded_labels))
    with _LABEL_LOCK:
        _LABEL_FILE_CACHE[cache_key] = cached_labels
        configure_sql_id_labels(cached_labels)


def re_load_sql_id_labels_from_file(path: str | os.PathLike[str]) -> None:
    """Alias for reload_sql_id_labels_from_file()."""
    reload_sql_id_labels_from_file(path)


def clear_sql_id_labels() -> None:
    """Clear the local label-name lookup."""
    global _LABELS_BY_NAME, _LABEL_NAMES_BY_ID

    with _LABEL_LOCK:
        _LABELS_BY_NAME = MappingProxyType({})
        _LABEL_NAMES_BY_ID = MappingProxyType({})
        _LABEL_FILE_CACHE.clear()


def available_labels() -> dict[str, int]:
    """Return a copy of the configured local label-name lookup."""
    with _LABEL_LOCK:
        return dict(_LABELS_BY_NAME)


def _label_name_for_id(label_id: int) -> str | None:
    with _LABEL_LOCK:
        return _LABEL_NAMES_BY_ID.get(label_id)


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


@lru_cache(maxsize=16)
def _derive_material(password_bytes: bytes, layout: SqlIdLayout) -> tuple[tuple[bytes, ...], bytes]:
    """Derive layout-specific Feistel round keys and validation-tag key."""
    seed = hmac.new(
        password_bytes,
        _DOMAIN_SALT + b":xctx-sql-id-label-layout:" + layout.domain_label() + b":seed:",
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
    """Return configured key material for the fixed layout or raise an error."""
    if layout != DEFAULT_LAYOUT or not _registry_is_sane():
        raise _ConfigError("invalid sql_id_library layout")
    return _derive_material(_password_bytes(), layout)


def is_configured() -> bool:
    """Return whether the module has enough configuration to encode/decode IDs."""
    try:
        _key_material(DEFAULT_LAYOUT)
        return True
    except Exception:  # noqa: BLE001 - configuration probe must not crash callers
        return False


def _coerce_id(value: object, layout: SqlIdLayout = DEFAULT_LAYOUT) -> int:
    """Strictly coerce a public input into an integer SQL ID."""
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
            raise _InputError("id string too long for uint32 range")
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
    """Encrypt one layout-width integer using the secret-derived Feistel PRP."""
    if not 0 <= value <= layout.value_mask:
        raise ValueError("value is outside layout range")

    left = (value >> layout.half_bits) & layout.half_mask
    right = value & layout.half_mask

    for key in round_keys:
        left, right = right, (left ^ _round_function(right, key, layout)) & layout.half_mask

    return ((left << layout.half_bits) | right) & layout.value_mask


def _feistel_decrypt(value: int, round_keys: tuple[bytes, ...], layout: SqlIdLayout = DEFAULT_LAYOUT) -> int:
    """Decrypt one layout-width integer using the secret-derived Feistel PRP."""
    if not 0 <= value <= layout.value_mask:
        raise ValueError("value is outside layout range")

    left = (value >> layout.half_bits) & layout.half_mask
    right = value & layout.half_mask

    for key in reversed(round_keys):
        left, right = (right ^ _round_function(left, key, layout)) & layout.half_mask, left

    return ((left << layout.half_bits) | right) & layout.value_mask


def _tag(version: int, label_id: int, id_index: int, tag_key: bytes, layout: SqlIdLayout = DEFAULT_LAYOUT) -> int:
    """Return a keyed validation tag for version, label, and id-index."""
    if not 0 <= version <= layout.version_mask:
        raise ValueError("version out of range")
    if not 0 <= label_id <= layout.label_mask:
        raise ValueError("label out of range")
    if not 0 <= id_index <= layout.id_mask:
        raise ValueError("id index out of range")

    message = (
        layout.domain_label()
        + b":version:"
        + version.to_bytes(1, "big")
        + b":label:"
        + label_id.to_bytes(1, "big")
        + b":id-index:"
        + id_index.to_bytes(layout.id_bytes, "big")
    )
    digest = hmac.new(tag_key, message, hashlib.sha256).digest()
    return int.from_bytes(digest[: layout.tag_bytes], "big") & layout.tag_mask


def _tags_equal(left: int, right: int, layout: SqlIdLayout = DEFAULT_LAYOUT) -> bool:
    """Compare compact integer tags without data-dependent short-circuiting."""
    return hmac.compare_digest(
        (left & layout.tag_mask).to_bytes(layout.tag_bytes, "big"),
        (right & layout.tag_mask).to_bytes(layout.tag_bytes, "big"),
    )


def _pack_plain(
    version: int,
    label_id: int,
    id_index: int,
    tag_key: bytes,
    layout: SqlIdLayout = DEFAULT_LAYOUT,
) -> int:
    """Pack version, label, zero-based ID index, and keyed tag into 64 bits."""
    if not 0 <= version <= layout.version_mask:
        raise ValueError("version out of range")
    if not 0 <= label_id <= layout.label_mask:
        raise ValueError("label out of range")
    if not 0 <= id_index < layout.max_id:
        raise ValueError("id index out of public range")

    tag = _tag(version, label_id, id_index, tag_key, layout)
    return (
        ((version & layout.version_mask) << (layout.label_bits + layout.id_bits + layout.tag_bits))
        | ((label_id & layout.label_mask) << (layout.id_bits + layout.tag_bits))
        | ((id_index & layout.id_mask) << layout.tag_bits)
        | tag
    ) & layout.value_mask


def _unpack_plain(value: int, layout: SqlIdLayout = DEFAULT_LAYOUT) -> tuple[int, int, int, int]:
    """Unpack a 64-bit plaintext value into version, label, id-index, and tag."""
    if not 0 <= value <= layout.value_mask:
        raise ValueError("value is outside layout range")

    version = (value >> (layout.label_bits + layout.id_bits + layout.tag_bits)) & layout.version_mask
    label_id = (value >> (layout.id_bits + layout.tag_bits)) & layout.label_mask
    id_index = (value >> layout.tag_bits) & layout.id_mask
    tag = value & layout.tag_mask
    return version, label_id, id_index, tag


def _encode_with_label(id_value: object, label_id: int) -> str | None:
    try:
        sql_id = _coerce_id(id_value, DEFAULT_LAYOUT)
        round_keys, tag_key = _key_material(DEFAULT_LAYOUT)
        plain = _pack_plain(ISSUE_VERSION, label_id, sql_id - 1, tag_key, DEFAULT_LAYOUT)
        encrypted = _feistel_encrypt(plain, round_keys, DEFAULT_LAYOUT)
        return f"{encrypted:0{HEX_CHARS}x}"
    except Exception:  # noqa: BLE001 - public convenience API returns None
        return None


def id_to_hex(value: object) -> str | None:
    """Return an unlabeled lowercase public hex ID, or None on any failure."""
    return _encode_with_label(value, NO_LABEL)


def id_to_hex_label(value: object, label: object) -> str | None:
    """Return a labeled lowercase public hex ID for label IDs 1..30."""
    try:
        label_id = _coerce_label(label, allow_zero=False)
    except Exception:
        return None
    return _encode_with_label(value, label_id)


def sql_generate_id(id_required: object) -> str | None:
    """Alias for id_to_hex(): give me unlabeled hex from an id."""
    return id_to_hex(id_required)


def sql_generate_id_label(id_required: object, label: object) -> str | None:
    """Alias for id_to_hex_label(): give me labeled hex from an id."""
    return id_to_hex_label(id_required, label)


def _validation_error(
    code: str,
    message: str,
    *,
    public_hex: str | None = None,
    layout: SqlIdLayout | None = None,
    version: int | None = None,
    label_id: int | None = None,
) -> SqlIdValidation:
    return SqlIdValidation(
        ok=False,
        public_hex=public_hex,
        label_id=label_id,
        label=_label_name_for_id(label_id) if label_id is not None else None,
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
        version, label_id, id_index, supplied_tag = _unpack_plain(plain, DEFAULT_LAYOUT)

        expected_tag = _tag(version, label_id, id_index, tag_key, DEFAULT_LAYOUT)
        if not _tags_equal(supplied_tag, expected_tag, DEFAULT_LAYOUT):
            raise _ValidationFailure("tag_mismatch", "public id validation tag does not match")
        if version not in ACTIVE_DECODE_VERSIONS:
            raise _ValidationFailure("unsupported_version", "public id uses an inactive version")
        if label_id == RESERVED_LABEL:
            raise _ValidationFailure("reserved_label", "public id uses a reserved label")
        if expected_label is not None and label_id != expected_label:
            raise _ValidationFailure("label_mismatch", "public id label does not match the expected label")
        if not 0 <= id_index < DEFAULT_LAYOUT.max_id:
            raise _ValidationFailure("id_out_of_range", "decoded id is outside the public range")

        id_value = id_index + 1
        if not MIN_ID <= id_value <= DEFAULT_LAYOUT.max_id:
            raise _ValidationFailure("id_out_of_range", "decoded id is outside the public range")

        return SqlIdValidation(
            ok=True,
            id=id_value,
            public_hex=public_hex,
            label_id=label_id,
            label=_label_name_for_id(label_id),
            version=version,
            layout=DEFAULT_LAYOUT,
        )
    except _ConfigError as exc:
        return _validation_error("bad_config", str(exc), public_hex=public_hex, layout=DEFAULT_LAYOUT)
    except _ValidationFailure as exc:
        return _validation_error(
            exc.code,
            exc.message,
            public_hex=public_hex,
            layout=DEFAULT_LAYOUT,
            version=locals().get("version"),
            label_id=locals().get("label_id"),
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
    """Alias for hex_to_id(): give me an id from unlabeled hex."""
    return hex_to_id(value)


def sql_decode_id_label(value: object, label: object) -> int | None:
    """Alias for hex_to_id_label(): give me an id from labeled hex."""
    return hex_to_id_label(value, label)


def hex_to_parts(value: object) -> tuple[int, str | None, int, int] | None:
    """Return (label_id, label_name, version, integer_id) for any valid ID."""
    result = inspect_hex(value)
    if not result.ok or result.id is None or result.label_id is None or result.version is None:
        return None
    return result.label_id, result.label, result.version, result.id
