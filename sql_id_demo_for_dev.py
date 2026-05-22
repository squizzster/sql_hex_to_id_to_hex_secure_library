#!/usr/bin/env python3
"""Developer demo and tiny CLI for sql_id_library.py.

Run:
    ./sql_id_demo_for_dev.py
    ./sql_id_demo_for_dev.py --int_id 1
    ./sql_id_demo_for_dev.py --int_id 1 --label users
    ./sql_id_demo_for_dev.py --hex_id 65a5cb411fa554a0

For real applications, set XCTX_ID_PASSWORD yourself with a strong secret:
    export XCTX_ID_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(32))')"
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence


DEMO_HARD_CODED_PASSWORD = "demo-hard-coded-secret-" + ("0123456789abcdef" * 4)
DEMO_LABELS = {"users": 1, "plans": 2, "repair": 3}
USING_DEMO_HARD_CODED_PASSWORD = False

from sql_id_library import (  # noqa: E402 - demo config is set before first probe
    ENV_PASSWORD_NAME,
    HEX_CHARS,
    ID_BITS,
    ISSUE_VERSION,
    LABEL_BITS,
    MAX_ID,
    MAX_LABEL,
    NO_LABEL,
    RESERVED_LABEL,
    TAG_BITS,
    TOTAL_BITS,
    VERSION_BITS,
    available_labels,
    configure_sql_id_labels,
    hex_to_id,
    hex_to_id_label,
    hex_to_parts,
    id_to_hex,
    id_to_hex_label,
    inspect_hex,
    is_configured,
    load_sql_id_labels_from_file,
    validate_hex,
    validate_hex_label,
)


def ensure_demo_config(*, strict: bool) -> None:
    """Use real env config if valid; otherwise create an in-process demo secret."""
    global USING_DEMO_HARD_CODED_PASSWORD

    if is_configured():
        return
    if strict:
        raise SystemExit(
            f"{ENV_PASSWORD_NAME} is missing or invalid. Set it with:\n"
            "  export XCTX_ID_PASSWORD=\"$(python -c 'import secrets; print(secrets.token_hex(32))')\""
        )

    USING_DEMO_HARD_CODED_PASSWORD = True
    os.environ["XCTX_ID_PASSWORD"] = DEMO_HARD_CODED_PASSWORD
    print(
        "Using DEMO_HARD_CODED_PASSWORD for XCTX_ID_PASSWORD. "
        f"To reproduce this demo run: export XCTX_ID_PASSWORD={DEMO_HARD_CODED_PASSWORD!r}",
        file=sys.stderr,
    )


def parse_label(value: str | None) -> str | int | None:
    """Parse CLI labels as configured names or numeric label IDs."""
    if value is None:
        return None
    if value.isdecimal():
        return int(value)
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="./sql_id_demo_for_dev.py",
        description=(
            "Developer demo for sql_id_library: explain the fixed 16-character "
            "layout, or encode/decode one ID."
        ),
        epilog=(
            "Examples:\n"
            "  ./sql_id_demo_for_dev.py\n"
            "  ./sql_id_demo_for_dev.py --int_id 1\n"
            "  ./sql_id_demo_for_dev.py --int_id 1 --label users\n"
            "  ./sql_id_demo_for_dev.py --labels-file ./conf/test_sql_id_labels.yaml --int_id 1 --label repair\n"
            "  ./sql_id_demo_for_dev.py --hex_id 65a5cb411fa554a0\n"
            "  ./sql_id_demo_for_dev.py --hex_id 65a5cb411fa554a0 --label users\n"
            "  ./sql_id_demo_for_dev.py --strict-config --int_id 1\n\n"
            "Demo label names are users=1, plans=2, repair=3. Numeric labels "
            "1..30 also work. Set XCTX_ID_PASSWORD for stable results across "
            "separate commands."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--int_id", type=int, help="encode this positive SQL integer ID and print public hex")
    action.add_argument("--hex_id", help="decode and validate this public hex ID and print the SQL integer ID")
    parser.add_argument("--label", help="use this expected label name or numeric label id")
    parser.add_argument("--labels-file", help="load label names from this .json, .yaml, or .yml file")
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
        f"label={validation.label}, version={validation.version}"
    )
    print()


def print_config_note() -> None:
    print(f"Configured: {is_configured()}")
    if USING_DEMO_HARD_CODED_PASSWORD:
        print(f"Using DEMO_HARD_CODED_PASSWORD for {ENV_PASSWORD_NAME}.")
        print("Real apps should set a stable secret in the process environment.")
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
    print("Turns positive SQL integer IDs into deterministic 16-character public hex handles.")
    print("Label 0 is ordinary/unlabeled. Labels 1..30 are explicit typed handles.")
    print("It is not an auth token; decode first, then apply normal authorization rules.")
    print()

    print("Bit layout")
    print("----------")
    print(f"total bits:   {TOTAL_BITS} ({HEX_CHARS} hex chars)")
    print(f"version bits: {VERSION_BITS} (currently issuing version {ISSUE_VERSION})")
    print(f"label bits:   {LABEL_BITS} ({NO_LABEL}=no label, 1..{MAX_LABEL}=named labels, {RESERVED_LABEL}=reserved)")
    print(f"id bits:      {ID_BITS} (SQL IDs 1..{MAX_ID:,})")
    print(f"tag bits:     {TAG_BITS}")
    print("plain value:  [ version ][ label ][ zero-based SQL id index ][ keyed validation tag ]")
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
    show_round_trip(123_456_789, label="users")

    print("Type enforcement:")
    user_hex = id_to_hex_label(42, "users")
    assert user_hex is not None
    print(f"users:42 public ID:            {user_hex}")
    print(f"hex_to_id(users ID):           {hex_to_id(user_hex)}")
    print(f"hex_to_id_label(..., users):   {hex_to_id_label(user_hex, 'users')}")
    print(f"hex_to_id_label(..., repair):  {hex_to_id_label(user_hex, 'repair')}")
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
    print("  ./sql_id_demo_for_dev.py --int_id 1")
    print("  ./sql_id_demo_for_dev.py --int_id 1 --label users")
    print("  ./sql_id_demo_for_dev.py --labels-file ./conf/test_sql_id_labels.yaml --int_id 1 --label repair")
    print("  ./sql_id_demo_for_dev.py --hex_id \"<public_hex>\"")
    print("  ./sql_id_demo_for_dev.py --hex_id \"<public_hex>\" --label users")
    print("  ./sql_id_demo_for_dev.py --help")


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
        print(f"version={result.version}")
        print(f"hex_chars={HEX_CHARS}")
        print(f"max_id={MAX_ID}")


def main(argv: Sequence[str] | None = None) -> None:
    configure_sql_id_labels(DEMO_LABELS)
    parser = build_parser()
    args = parser.parse_args(argv)
    ensure_demo_config(strict=args.strict_config)
    if args.labels_file is not None:
        load_sql_id_labels_from_file(args.labels_file)
    label = parse_label(args.label)

    if args.int_id is not None:
        encode_cli(args.int_id, label=label, details=args.details)
        return
    if args.hex_id is not None:
        decode_cli(args.hex_id, label=label, details=args.details)
        return
    show_default_demo()


if __name__ == "__main__":
    main()
