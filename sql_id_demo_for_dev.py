#!/usr/bin/env python3
"""Developer demo and tiny CLI for sql_id_library.py.

Run:
    ./sql_id_demo_for_dev.py
    ./sql_id_demo_for_dev.py --int_id 1
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
USING_DEMO_HARD_CODED_PASSWORD = False

from sql_id_library import (  # noqa: E402 - demo config is set before first probe
    DEFAULT_PROFILE,
    ENV_PASSWORD_NAME,
    ISSUE_VERSION,
    VERSION_BITS,
    available_layouts,
    hex_to_id,
    hex_to_parts,
    id_to_hex,
    is_configured,
    layout_for_profile,
    validate_hex,
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="./sql_id_demo_for_dev.py",
        description=(
            "Developer demo for sql_id_library: explain layouts by default, "
            "or encode/decode one ID."
        ),
        epilog=(
            "Examples:\n"
            "  ./sql_id_demo_for_dev.py\n"
            "  ./sql_id_demo_for_dev.py --int_id 1\n"
            "  ./sql_id_demo_for_dev.py --int_id 1 --profile uint16\n"
            "  ./sql_id_demo_for_dev.py --int_id 1 --boosted\n"
            "  ./sql_id_demo_for_dev.py --hex_id 65a5cb411fa554a0\n"
            "  ./sql_id_demo_for_dev.py --strict-config --int_id 1\n\n"
            "Set XCTX_ID_PASSWORD for stable results across separate commands."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--int_id", type=int, help="encode this positive SQL integer ID and print public hex")
    action.add_argument("--hex_id", help="decode and validate this public hex ID and print the SQL integer ID")
    parser.add_argument(
        "--profile",
        choices=[layout.profile for layout in available_layouts() if layout.mode == "normal"],
        default=DEFAULT_PROFILE,
        help="encoding profile for --int_id; decode is always length-driven",
    )
    parser.add_argument("--boosted", action="store_true", help="use boosted layout when encoding --int_id")
    parser.add_argument(
        "--strict-config",
        action="store_true",
        help=f"fail instead of generating a demo-only {ENV_PASSWORD_NAME}",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="with --int_id or --hex_id, also print layout and validation details",
    )
    return parser


def show_round_trip(sql_id: int, *, profile: str = "uint32", boosted: bool = False) -> None:
    """Encode one SQL ID, decode it, and print validation details."""
    public_hex = id_to_hex(sql_id, profile=profile, boosted=boosted)
    if public_hex is None:
        raise RuntimeError(f"could not encode SQL ID {sql_id!r}")

    validation = validate_hex(public_hex)

    print(f"SQL ID:     {sql_id}")
    print(f"Public ID:  {public_hex}")
    print(f"Decoded ID: {hex_to_id(public_hex)}")
    print(f"Parts:      {hex_to_parts(public_hex)}")
    print(
        "Validated:  "
        f"ok={validation.ok}, profile={validation.profile}, "
        f"mode={validation.mode}, version={validation.version}"
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
    print("Turns positive SQL integer IDs into deterministic public hex handles.")
    print("The handle hides sequential IDs and rejects almost all random or tampered strings.")
    print("It is not an auth token; decode first, then apply normal authorization rules.")
    print()

    print("Bit layout")
    print("----------")
    print(f"version bits: {VERSION_BITS} (currently issuing version {ISSUE_VERSION})")
    print("plain value:  [ version ][ zero-based SQL id index ][ keyed validation tag ]")
    print("public hex:   Feistel permutation of that plain value, encoded as lowercase hex")
    print("decode:       public hex length selects exactly one layout")
    print()

    print("Default uint32 normal layout:")
    show_round_trip(123_456_789)

    print("A shorter uint16 public ID:")
    show_round_trip(42, profile="uint16")

    print("A boosted uint32 public ID with a longer validation tag:")
    show_round_trip(123_456_789, profile="uint32", boosted=True)

    print("Tamper check:")
    valid_hex = id_to_hex(42)
    assert valid_hex is not None
    tampered_hex = valid_hex[:-1] + ("0" if valid_hex[-1] != "0" else "1")
    result = validate_hex(tampered_hex)
    print(f"Original:   {valid_hex}")
    print(f"Tampered:   {tampered_hex}")
    print(f"Validation: ok={result.ok}, error_code={result.error_code}")
    print()

    print("Layout table")
    print("------------")
    rows: list[list[object]] = [["profile", "mode", "id bits", "tag bits", "hex chars", "max SQL ID"]]
    for layout in available_layouts():
        rows.append(
            [
                layout.profile,
                layout.mode,
                layout.id_bits,
                layout.tag_bits,
                layout.hex_chars,
                f"{layout.max_id:,}",
            ]
        )
    print_table(rows)
    print()

    print("CLI commands")
    print("------------")
    print("  ./sql_id_demo_for_dev.py --int_id 1")
    print("  ./sql_id_demo_for_dev.py --hex_id \"<public_hex>\"")
    print("  ./sql_id_demo_for_dev.py --int_id 1 --profile uint16")
    print("  ./sql_id_demo_for_dev.py --int_id 1 --boosted")
    print("  ./sql_id_demo_for_dev.py --help")


def encode_cli(sql_id: int, *, profile: str, boosted: bool, details: bool) -> None:
    public_hex = id_to_hex(sql_id, profile=profile, boosted=boosted)
    if public_hex is None:
        raise SystemExit(f"could not encode {sql_id!r} with profile={profile!r}, boosted={boosted}")
    print(public_hex)
    if details:
        layout = layout_for_profile(profile, boosted=boosted)
        validation = validate_hex(public_hex)
        print(f"int_id={sql_id}")
        print(f"profile={validation.profile}")
        print(f"mode={validation.mode}")
        print(f"version={validation.version}")
        if layout is not None:
            print(f"hex_chars={layout.hex_chars}")
            print(f"max_id={layout.max_id}")


def decode_cli(public_hex: str, *, details: bool) -> None:
    result = validate_hex(public_hex)
    if not result.ok or result.id is None:
        raise SystemExit(f"invalid public hex: {result.error_code} ({result.error})")
    print(result.id)
    if details:
        print(f"hex_id={result.public_hex}")
        print(f"profile={result.profile}")
        print(f"mode={result.mode}")
        print(f"version={result.version}")
        if result.layout is not None:
            print(f"hex_chars={result.layout.hex_chars}")
            print(f"max_id={result.layout.max_id}")


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    ensure_demo_config(strict=args.strict_config)

    if args.int_id is not None:
        encode_cli(args.int_id, profile=args.profile, boosted=args.boosted, details=args.details)
        return
    if args.hex_id is not None:
        decode_cli(args.hex_id, details=args.details)
        return
    show_default_demo()


if __name__ == "__main__":
    main()
