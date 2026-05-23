#!/usr/bin/env python3
"""Developer demo CLI for sql_id_library.py.

Run:
    ./bin_demo/sql_id_demo_for_dev.py
    ./bin_demo/sql_id_demo_for_dev.py --int_id 1
    ./bin_demo/sql_id_demo_for_dev.py --int_id 1 --label repair
    ./bin_demo/sql_id_demo_for_dev.py --hex_id f4b745ba77dc1096d657a861e3f80842

For real applications, set SQL_ID_LIBRARY_PASSWORD_HEX_v1 with a strong hex secret:
    export SQL_ID_LIBRARY_PASSWORD_HEX_v1="$(python -c 'import secrets; print(secrets.token_hex(32))')"

Also set SQL_ID_LIBRARY_DOMAIN_SALT_HEX_v1 and create a v1 pepper file for deployed
public IDs.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path


DEMO_HARD_CODED_DOMAIN_SALT_HEX = "0b91b4e8fd74bcb256a19d188c83470a7b75a4897babb252e54b6eb8f8bb392d"
DEMO_HARD_CODED_PASSWORD = "00112233445566778899aabbccddeeff" * 2
DEMO_HARD_CODED_PEPPER_HEX = "abcdef0123456789" * 4
USING_DEMO_HARD_CODED_DOMAIN_SALT = False
USING_DEMO_HARD_CODED_PASSWORD = False
USING_DEMO_HARD_CODED_PEPPER = False
_DEMO_ENV_RESTORE: dict[str, str | None] = {}
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEMO_CONFIG_PATH = PROJECT_ROOT / "conf" / "test_sql_id_config.yaml"
DEMO_PEPPER_PATH = Path("/tmp/sql_id_library_demo_pepper_please_create_your_own_and_delete_me_v1.key")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sql_id_library import (  # noqa: E402 - demo config is set before first probe
    DEFAULT_PEPPER_FILE_LOCATION,
    ENV_DOMAIN_SALT_NAME,
    ENV_PASSWORD_NAME,
    HEX_CHARS,
    BIGINT_RANGE_CLASS,
    BIGINT_RANGE_MIN_ID,
    BIGINT_TAG_BITS,
    MAX_ID_BITS,
    LABEL_BITS,
    MAX_ID,
    MAX_LABEL,
    MAX_DOMAIN_SALT_BYTES,
    MAX_DOMAIN_SALT_HEX_CHARS,
    MAX_PASSWORD_BYTES,
    MAX_PASSWORD_HEX_CHARS,
    MIN_DOMAIN_SALT_BYTES,
    MIN_DOMAIN_SALT_HEX_CHARS,
    MIN_DOMAIN_SALT_UNIQUE_BYTES,
    NO_LABEL,
    RANGE_BITS,
    RESERVED_LABEL,
    MIN_PASSWORD_BYTES,
    MIN_PASSWORD_HEX_CHARS,
    MIN_PASSWORD_UNIQUE_BYTES,
    SMALL_RANGE_CLASS,
    SMALL_RANGE_MAX_ID,
    SMALL_TAG_BITS,
    TOTAL_BITS,
    VERSION_BITS,
    available_labels,
    configure_sql_id,
    configured_pepper_file_location,
    configured_issue_version,
    hex_to_id,
    hex_to_id_label,
    hex_to_parts,
    id_to_hex,
    id_to_hex_label,
    inspect_hex,
    is_configured,
    load_sql_id_config_from_file,
    validate_hex,
    validate_hex_label,
    _decode_config_hex,
)


def demo_key_hex_is_valid(
    *,
    name: str,
    value: object,
    min_hex_chars: int,
    max_hex_chars: int,
    min_bytes: int,
    max_bytes: int,
    min_unique_bytes: int,
) -> bool:
    try:
        _decode_config_hex(
            name=name,
            value=value,
            min_hex_chars=min_hex_chars,
            max_hex_chars=max_hex_chars,
            min_bytes=min_bytes,
            max_bytes=max_bytes,
            min_unique_bytes=min_unique_bytes,
        )
    except ValueError:
        return False
    return True


def set_temporary_demo_env(name: str, value: str) -> None:
    """Set an environment value for this demo process and remember how to restore it."""
    if name not in _DEMO_ENV_RESTORE:
        _DEMO_ENV_RESTORE[name] = os.environ.get(name)
    os.environ[name] = value


def restore_temporary_demo_env() -> None:
    """Restore environment values changed by the demo."""
    while _DEMO_ENV_RESTORE:
        name, old_value = _DEMO_ENV_RESTORE.popitem()
        if old_value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = old_value


def ensure_demo_config(*, strict: bool) -> None:
    """Use real env config if valid; otherwise create an in-process demo secret."""
    global USING_DEMO_HARD_CODED_DOMAIN_SALT, USING_DEMO_HARD_CODED_PASSWORD, USING_DEMO_HARD_CODED_PEPPER

    if is_configured():
        return
    if strict:
        raise SystemExit(
            f"{ENV_DOMAIN_SALT_NAME}, {ENV_PASSWORD_NAME}, the pepper file, or some combination is missing or invalid. "
            "Configure them with:\n"
            f"  export {ENV_DOMAIN_SALT_NAME}=\"$(python -c 'import secrets; print(secrets.token_hex(32))')\"\n"
            f"  export {ENV_PASSWORD_NAME}=\"$(python -c 'import secrets; print(secrets.token_hex(32))')\"\n"
            f"  python -c \"import secrets; print(secrets.token_hex(32))\" > {DEFAULT_PEPPER_FILE_LOCATION}\n"
            f"  chmod 0400 {DEFAULT_PEPPER_FILE_LOCATION}"
        )

    domain_salt = os.environ.get(ENV_DOMAIN_SALT_NAME)
    if not demo_key_hex_is_valid(
        name=ENV_DOMAIN_SALT_NAME,
        value=domain_salt,
        min_hex_chars=MIN_DOMAIN_SALT_HEX_CHARS,
        max_hex_chars=MAX_DOMAIN_SALT_HEX_CHARS,
        min_bytes=MIN_DOMAIN_SALT_BYTES,
        max_bytes=MAX_DOMAIN_SALT_BYTES,
        min_unique_bytes=MIN_DOMAIN_SALT_UNIQUE_BYTES,
    ):
        USING_DEMO_HARD_CODED_DOMAIN_SALT = True
        set_temporary_demo_env(ENV_DOMAIN_SALT_NAME, DEMO_HARD_CODED_DOMAIN_SALT_HEX)
        print(
            f"Using demo-only in-process {ENV_DOMAIN_SALT_NAME}. "
            "Real applications should set their own stable value.",
            file=sys.stderr,
        )

    password = os.environ.get(ENV_PASSWORD_NAME)
    if not demo_key_hex_is_valid(
        name=ENV_PASSWORD_NAME,
        value=password,
        min_hex_chars=MIN_PASSWORD_HEX_CHARS,
        max_hex_chars=MAX_PASSWORD_HEX_CHARS,
        min_bytes=MIN_PASSWORD_BYTES,
        max_bytes=MAX_PASSWORD_BYTES,
        min_unique_bytes=MIN_PASSWORD_UNIQUE_BYTES,
    ):
        USING_DEMO_HARD_CODED_PASSWORD = True
        set_temporary_demo_env(ENV_PASSWORD_NAME, DEMO_HARD_CODED_PASSWORD)
        print(
            f"Using demo-only in-process {ENV_PASSWORD_NAME}. "
            "Real applications should set their own stable value.",
            file=sys.stderr,
        )

    ensure_demo_pepper_file()
    configure_sql_id({"pepper_file_location": str(DEMO_PEPPER_PATH)})
    USING_DEMO_HARD_CODED_PEPPER = True
    print(
        f"Using demo pepper file at {DEMO_PEPPER_PATH}. "
        f"Real applications should create {DEFAULT_PEPPER_FILE_LOCATION} with chmod 0400.",
        file=sys.stderr,
    )

    if not is_configured():
        raise SystemExit("demo configuration is still invalid after creating demo password and pepper")


def ensure_demo_pepper_file() -> None:
    """Create the demo pepper once without following symlinks or clobbering."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if os.name == "posix":
        flags |= getattr(os, "O_NOFOLLOW", 0)

    try:
        fd = os.open(DEMO_PEPPER_PATH, flags, 0o400)
    except FileExistsError:
        if os.name == "posix":
            try:
                file_stat = DEMO_PEPPER_PATH.lstat()
            except OSError as exc:
                raise SystemExit(f"could not inspect existing demo pepper file: {exc}") from exc
            if stat.S_ISLNK(file_stat.st_mode):
                raise SystemExit(f"demo pepper path is a symlink; delete it first: {DEMO_PEPPER_PATH}")
            if hasattr(os, "geteuid") and file_stat.st_uid != os.geteuid():
                raise SystemExit(f"demo pepper path is not owned by this user; delete it first: {DEMO_PEPPER_PATH}")
        return
    except OSError as exc:
        raise SystemExit(f"could not create demo pepper file: {exc}") from exc

    try:
        payload = (DEMO_HARD_CODED_PEPPER_HEX + "\n").encode("ascii")
        if os.write(fd, payload) != len(payload):
            raise SystemExit(f"could not fully write demo pepper file: {DEMO_PEPPER_PATH}")
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o400)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def parse_label(value: str | None) -> str | int | None:
    """Parse CLI labels as configured names or numeric label IDs."""
    if value is None:
        return None
    if value.isdecimal():
        return int(value)
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="./bin_demo/sql_id_demo_for_dev.py",
        description=(
            "Developer demo for sql_id_library: explain the fixed 32-character "
            "layout, or encode/decode one ID."
        ),
        epilog=(
            "Examples:\n"
            "  ./bin_demo/sql_id_demo_for_dev.py\n"
            "  ./bin_demo/sql_id_demo_for_dev.py --int_id 1\n"
            "  ./bin_demo/sql_id_demo_for_dev.py --int_id 1 --label repair\n"
            "  ./bin_demo/sql_id_demo_for_dev.py --config-file ./conf/test_sql_id_config.yaml --int_id 1 --label repair\n"
            "  ./bin_demo/sql_id_demo_for_dev.py --hex_id f4b745ba77dc1096d657a861e3f80842\n"
            "  ./bin_demo/sql_id_demo_for_dev.py --hex_id 99022391110b81bfe4bf80f3bde16ea2 --label repair\n"
            "  ./bin_demo/sql_id_demo_for_dev.py --strict-config --int_id 1\n\n"
            "Demo labels are loaded from ./conf/test_sql_id_config.yaml: "
            "dry_run=1, plan=2, execute=3, enquire=4, repair=5. Numeric labels "
            f"1..30 also work. Set {ENV_DOMAIN_SALT_NAME} and "
            f"{ENV_PASSWORD_NAME} for stable results across separate commands."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--int_id", type=int, help="encode this positive SQL BIGINT ID and print public hex")
    action.add_argument("--hex_id", help="strictly decode this public hex ID and print the SQL BIGINT ID")
    parser.add_argument("--label", help="label name or numeric label id to encode with, or to require when decoding")
    parser.add_argument("--config-file", help="configure labels and/or pepper path from this .json, .yaml, or .yml file")
    parser.add_argument(
        "--strict-config",
        action="store_true",
        help=f"fail instead of generating a demo-only {ENV_PASSWORD_NAME}",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="with --int_id or --hex_id, also print validation details",
    )
    return parser


def show_round_trip(sql_id: int, *, label: str | int | None = None) -> None:
    """Encode one SQL ID, decode it, and print validation details."""
    if label is None:
        public_hex = id_to_hex(sql_id)
        decoded = hex_to_id(public_hex)
        validation = validate_hex(public_hex)
        label_text = "none"
    else:
        public_hex = id_to_hex_label(sql_id, label)
        decoded = hex_to_id_label(public_hex, label)
        validation = validate_hex_label(public_hex, label)
        label_text = str(label)

    if public_hex is None:
        raise RuntimeError(f"could not encode SQL ID {sql_id!r}")

    print(f"SQL ID:     {sql_id}")
    print(f"Label:      {label_text}")
    print(f"Public ID:  {public_hex}")
    print(f"Decoded ID: {decoded}")
    print(f"Parts:      {hex_to_parts(public_hex)}")
    print(
        "Validated:  "
        f"ok={validation.ok}, label_id={validation.label_id}, "
        f"label={validation.label}, range_class={validation.range_class}, "
        f"tag_bits={validation.tag_bits}, version={validation.version}"
    )
    print()


def print_config_note() -> None:
    print(f"Configured: {is_configured()}")
    if USING_DEMO_HARD_CODED_DOMAIN_SALT:
        print(f"Using demo-only in-process {ENV_DOMAIN_SALT_NAME}.")
        print("Real applications should set a stable domain salt in the process environment.")
    if USING_DEMO_HARD_CODED_PASSWORD:
        print(f"Using demo-only in-process {ENV_PASSWORD_NAME}.")
        print("Real applications should set a stable hex secret in the process environment.")
    if USING_DEMO_HARD_CODED_PEPPER:
        print(f"Using demo pepper file: {configured_pepper_file_location()}")
        print("Real applications should use a stable private readable pepper file.")
    print()


def print_table(rows: Sequence[Sequence[object]]) -> None:
    widths = [max(len(str(row[index])) for row in rows) for index in range(len(rows[0]))]
    for row_index, row in enumerate(rows):
        print("  " + "  ".join(str(value).ljust(widths[index]) for index, value in enumerate(row)))
        if row_index == 0:
            print("  " + "  ".join("-" * width for width in widths))


def show_default_demo() -> None:
    print("SQL ID library developer demo")
    print("=============================")
    print_config_note()

    print("What this library does")
    print("----------------------")
    print("Turns positive SQL BIGINT IDs into deterministic 32-character public hex handles.")
    print("Label 0 is unlabeled. Labels 1..30 are explicit typed handles.")
    print("It is not an auth token; decode first, then apply normal authorization rules.")
    print()

    print("Bit layout")
    print("----------")
    print(f"total bits:   {TOTAL_BITS} ({HEX_CHARS} hex chars)")
    print(f"version bits: {VERSION_BITS} (currently issuing version {configured_issue_version()})")
    print(
        f"label bits:   {LABEL_BITS} "
        f"({NO_LABEL}=no label, 1..{MAX_LABEL}=named labels, {RESERVED_LABEL}=reserved)"
    )
    print(
        f"range bits:   {RANGE_BITS} "
        f"({SMALL_RANGE_CLASS}=32-bit ID field, {BIGINT_RANGE_CLASS}=64-bit ID field)"
    )
    print(f"id bits:      up to {MAX_ID_BITS} (SQL BIGINT IDs 1..{MAX_ID:,})")
    print(
        f"tag bits:     {SMALL_TAG_BITS} for IDs 1..{SMALL_RANGE_MAX_ID:,}; "
        f"{BIGINT_TAG_BITS} for IDs {BIGINT_RANGE_MIN_ID:,}..{MAX_ID:,}"
    )
    print("plain value:  [ version ][ label ][ range ][ SQL id ][ keyed validation tag ]")
    print("public hex:   Feistel permutation of that plain value, encoded as lowercase hex")
    print()

    print("Configured demo labels")
    print("----------------------")
    rows: list[list[object]] = [["name", "label id"]]
    for name, label_id in sorted(available_labels().items(), key=lambda item: item[1]):
        rows.append([name, label_id])
    print_table(rows)
    print()

    print("Unlabeled public ID:")
    show_round_trip(123_456_789)

    print("Labeled public ID:")
    show_round_trip(123_456_789, label="repair")

    print("Type enforcement:")
    repair_hex = id_to_hex_label(42, "repair")
    assert repair_hex is not None
    print(f"repair:42 public ID:           {repair_hex}")
    print(f"hex_to_id(repair ID):          {hex_to_id(repair_hex)}")
    print(f"hex_to_id_label(..., repair):  {hex_to_id_label(repair_hex, 'repair')}")
    print(f"hex_to_id_label(..., plan):    {hex_to_id_label(repair_hex, 'plan')}")
    print()

    print("Tamper check:")
    valid_hex = id_to_hex(42)
    assert valid_hex is not None
    tampered_hex = valid_hex[:-1] + ("0" if valid_hex[-1] != "0" else "1")
    result = inspect_hex(tampered_hex)
    print(f"Original:   {valid_hex}")
    print(f"Tampered:   {tampered_hex}")
    print(f"Validation: ok={result.ok}, error_code={result.error_code}")
    print()

    print("CLI commands")
    print("------------")
    print("  ./bin_demo/sql_id_demo_for_dev.py --int_id 1")
    print("  ./bin_demo/sql_id_demo_for_dev.py --int_id 1 --label repair")
    print("  ./bin_demo/sql_id_demo_for_dev.py --config-file ./conf/test_sql_id_config.yaml --int_id 1 --label repair")
    print("  ./bin_demo/sql_id_demo_for_dev.py --hex_id \"<public_hex>\"")
    print("  ./bin_demo/sql_id_demo_for_dev.py --hex_id \"<public_hex>\" --label repair")
    print("  ./bin_demo/sql_id_demo_for_dev.py --help")


def encode_cli(sql_id: int, *, label: str | int | None, details: bool) -> None:
    if label is None:
        public_hex = id_to_hex(sql_id)
        validation = validate_hex(public_hex)
    else:
        public_hex = id_to_hex_label(sql_id, label)
        validation = validate_hex_label(public_hex, label)

    if public_hex is None:
        raise SystemExit(f"could not encode {sql_id!r} with label={label!r}")

    print(public_hex)
    if details:
        print(f"int_id={sql_id}")
        print(f"label_id={validation.label_id}")
        print(f"label={validation.label}")
        print(f"range_class={validation.range_class}")
        print(f"tag_bits={validation.tag_bits}")
        print(f"version={validation.version}")
        print(f"hex_chars={HEX_CHARS}")
        print(f"max_id={MAX_ID}")


def decode_cli(public_hex: str, *, label: str | int | None, details: bool) -> None:
    if label is None:
        result = validate_hex(public_hex)
    else:
        result = validate_hex_label(public_hex, label)

    if not result.ok or result.id is None:
        raise SystemExit(f"invalid public hex: {result.error_code} ({result.error})")
    print(result.id)
    if details:
        print(f"hex_id={result.public_hex}")
        print(f"label_id={result.label_id}")
        print(f"label={result.label}")
        print(f"range_class={result.range_class}")
        print(f"tag_bits={result.tag_bits}")
        print(f"version={result.version}")
        print(f"hex_chars={HEX_CHARS}")
        print(f"max_id={MAX_ID}")


def main(argv: Sequence[str] | None = None) -> None:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        config_path = Path(args.config_file) if args.config_file is not None else DEFAULT_DEMO_CONFIG_PATH
        try:
            load_sql_id_config_from_file(config_path)
        except ValueError as exc:
            raise SystemExit(f"could not load SQL ID demo config {config_path}: {exc}") from exc
        ensure_demo_config(strict=args.strict_config)
        label = parse_label(args.label)

        if args.int_id is not None:
            encode_cli(args.int_id, label=label, details=args.details)
            return
        if args.hex_id is not None:
            decode_cli(args.hex_id, label=label, details=args.details)
            return
        show_default_demo()
    finally:
        restore_temporary_demo_env()


if __name__ == "__main__":
    main()
