#!/usr/bin/env python3
"""Tests for the layout-registry driven sql_id_library.py.

Run with:
    XCTX_ID_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(32))')" python test_sql_id.py

The tests set a safe default test password when one is not already present, then
also cover missing, weak, low-diversity, and wrong-password behavior.
"""

from __future__ import annotations

import os
import re
import unittest
from contextlib import contextmanager
from unittest import mock


TEST_PASSWORD = "unit-test-secret-" + ("0123456789abcdef" * 4)
OTHER_TEST_PASSWORD = "different-test-secret-" + ("fedcba9876543210" * 4)
os.environ.setdefault("XCTX_ID_PASSWORD", TEST_PASSWORD)

import sql_id_library as sid  # noqa: E402  - env default is set before import


@contextmanager
def patched_password(value: str | None):
    """Temporarily patch XCTX_ID_PASSWORD for tests."""
    old_present = sid.ENV_PASSWORD_NAME in os.environ
    old_value = os.environ.get(sid.ENV_PASSWORD_NAME)
    try:
        if value is None:
            os.environ.pop(sid.ENV_PASSWORD_NAME, None)
        else:
            os.environ[sid.ENV_PASSWORD_NAME] = value
        yield
    finally:
        if old_present and old_value is not None:
            os.environ[sid.ENV_PASSWORD_NAME] = old_value
        else:
            os.environ.pop(sid.ENV_PASSWORD_NAME, None)


class SqlIdLibraryTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ[sid.ENV_PASSWORD_NAME] = TEST_PASSWORD

    def assert_public_hex(self, value: object, *, profile: str = "uint32", boosted: bool = False) -> str:
        layout = sid.layout_for_profile(profile, boosted=boosted)
        self.assertIsNotNone(layout)
        assert layout is not None
        encoded = sid.id_to_hex(value, profile=profile, boosted=boosted)
        self.assertIsInstance(encoded, str)
        assert encoded is not None
        self.assertRegex(encoded, re.compile(rf"^[0-9a-f]{{{layout.hex_chars}}}$"))
        return encoded

    def test_registry_matches_final_normal_and_boosted_tables(self) -> None:
        expected = {
            ("uint8", "normal"): (8, 40, 10, 28),
            ("uint16", "normal"): (16, 48, 12, 28),
            ("uint24", "normal"): (24, 56, 14, 28),
            ("uint32", "normal"): (32, 64, 16, 28),
            ("uint48", "normal"): (48, 80, 20, 28),
            ("uint64", "normal"): (64, 96, 24, 28),
            ("uint8", "boosted"): (8, 72, 18, 60),
            ("uint16", "boosted"): (16, 88, 22, 68),
            ("uint24", "boosted"): (24, 104, 26, 76),
            ("uint32", "boosted"): (32, 112, 28, 76),
            ("uint48", "boosted"): (48, 120, 30, 68),
            ("uint64", "boosted"): (64, 128, 32, 60),
        }

        self.assertEqual(sid.SCHEME_REVISION, 1)
        self.assertEqual(sid.VERSION_BITS, 4)
        self.assertEqual(sid.DEFAULT_PROFILE, "uint32")
        self.assertFalse(sid.DEFAULT_BOOSTED)
        self.assertEqual(sid.DEFAULT_LAYOUT.profile, "uint32")
        self.assertEqual(sid.DEFAULT_LAYOUT.mode, "normal")
        self.assertEqual(sid.ID_BITS, 32)
        self.assertEqual(sid.TAG_BITS, 28)
        self.assertEqual(sid.MAX_ID, (1 << 32) - 1)
        self.assertEqual(sid.MYSQL_UNSIGNED_INT_MAX, 4_294_967_295)
        self.assertGreaterEqual(sid.MIN_PASSWORD_BYTES, 32)
        self.assertGreaterEqual(sid.ROUNDS, 12)
        self.assertTrue(sid._constants_are_sane())

        actual = {
            (layout.profile, layout.mode): (
                layout.id_bits,
                layout.total_bits,
                layout.hex_chars,
                layout.tag_bits,
            )
            for layout in sid.LAYOUTS
        }
        self.assertEqual(actual, expected)

        for layout in sid.LAYOUTS:
            with self.subTest(layout=f"{layout.profile}/{layout.mode}"):
                self.assertEqual(layout.version_bits + layout.id_bits + layout.tag_bits, layout.total_bits)
                self.assertEqual(layout.hex_chars, layout.total_bits // 4)
                self.assertEqual(layout.bytes, layout.total_bits // 8)
                self.assertEqual(layout.max_id, (1 << layout.id_bits) - 1)
                self.assertEqual(layout.id_states, 1 << layout.id_bits)
                self.assertLess(layout.max_id, layout.id_states)

    def test_decode_length_map_is_unique_and_complete(self) -> None:
        expected_length_map = {
            10: ("uint8", "normal"),
            12: ("uint16", "normal"),
            14: ("uint24", "normal"),
            16: ("uint32", "normal"),
            20: ("uint48", "normal"),
            24: ("uint64", "normal"),
            18: ("uint8", "boosted"),
            22: ("uint16", "boosted"),
            26: ("uint24", "boosted"),
            28: ("uint32", "boosted"),
            30: ("uint48", "boosted"),
            32: ("uint64", "boosted"),
        }
        self.assertEqual(tuple(sorted(expected_length_map)), sid.SUPPORTED_HEX_LENGTHS)
        for hex_chars, (profile, mode) in expected_length_map.items():
            layout = sid.layout_for_hex_length(hex_chars)
            self.assertIsNotNone(layout)
            assert layout is not None
            self.assertEqual((layout.profile, layout.mode), (profile, mode))

    def test_public_api_trio(self) -> None:
        encoded = sid.sql_generate_id(123_456_789)
        self.assertIsInstance(encoded, str)
        assert encoded is not None
        self.assertEqual(len(encoded), 16)
        self.assertEqual(encoded, sid.id_to_hex(123_456_789))
        self.assertEqual(sid.sql_decode_id(encoded), 123_456_789)
        self.assertEqual(sid.hex_to_id(encoded), 123_456_789)

        result = sid.sql_validate_id(encoded)
        self.assertTrue(result.ok)
        self.assertEqual(result.id, 123_456_789)
        self.assertEqual(result.profile, "uint32")
        self.assertEqual(result.mode, "normal")
        self.assertEqual(result.version, sid.ISSUE_VERSION)
        self.assertIsNone(result.error)
        self.assertIsNone(result.error_code)

        self.assertEqual(sid.hex_to_parts(encoded), ("uint32", "normal", sid.ISSUE_VERSION, 123_456_789))

    def test_configuration_probe_and_config_errors(self) -> None:
        self.assertTrue(sid.is_configured())

        with patched_password(None):
            self.assertFalse(sid.is_configured())
            self.assertIsNone(sid.id_to_hex(1))
            result = sid.validate_hex("0" * sid.DEFAULT_LAYOUT.hex_chars)
            self.assertFalse(result.ok)
            self.assertEqual(result.error_code, "bad_config")
            self.assertIsNone(sid.hex_to_id("0" * sid.DEFAULT_LAYOUT.hex_chars))

        with patched_password("short"):
            self.assertFalse(sid.is_configured())
            self.assertIsNone(sid.id_to_hex(1))
            self.assertEqual(sid.validate_hex("0" * 16).error_code, "bad_config")

        with patched_password("a" * sid.MIN_PASSWORD_BYTES):
            self.assertFalse(sid.is_configured())
            self.assertIsNone(sid.id_to_hex(1))
            self.assertEqual(sid.validate_hex("0" * 16).error_code, "bad_config")

        with patched_password("0123456789abcdef" * 2):
            self.assertTrue(sid.is_configured())
            self.assertIsNotNone(sid.id_to_hex(1))

    def test_round_trips_edges_and_representative_values_for_every_layout(self) -> None:
        for layout in sid.LAYOUTS:
            representatives: list[object] = [1, 2, 12, "1", "000001"]
            if layout.max_id >= 999:
                representatives.append(999)
            examples: list[object] = representatives + [layout.max_id - 1, layout.max_id, str(layout.max_id)]
            for value in examples:
                with self.subTest(layout=f"{layout.profile}/{layout.mode}", value=value):
                    expected = int(value)
                    encoded = self.assert_public_hex(value, profile=layout.profile, boosted=layout.boosted)
                    self.assertEqual(len(encoded), layout.hex_chars)
                    self.assertEqual(sid.hex_to_id(encoded), expected)
                    self.assertEqual(sid.hex_to_id(encoded.upper()), expected)

                    result = sid.validate_hex(encoded)
                    self.assertTrue(result.ok)
                    self.assertEqual(result.id, expected)
                    self.assertEqual(result.profile, layout.profile)
                    self.assertEqual(result.mode, layout.mode)
                    self.assertEqual(result.layout, layout)

    def test_encoding_is_deterministic_for_same_password_and_layout(self) -> None:
        for layout in sid.LAYOUTS:
            if layout.max_id < 123:
                continue
            with self.subTest(layout=f"{layout.profile}/{layout.mode}"):
                first = self.assert_public_hex(123, profile=layout.profile, boosted=layout.boosted)
                second = self.assert_public_hex("123", profile=layout.profile, boosted=layout.boosted)
                third = self.assert_public_hex(123, profile=layout.profile, boosted=layout.boosted)
                self.assertEqual(first, second)
                self.assertEqual(second, third)

    def test_same_id_across_layouts_uses_layout_domain_separation(self) -> None:
        encoded_by_layout = {
            (layout.profile, layout.mode): self.assert_public_hex(42, profile=layout.profile, boosted=layout.boosted)
            for layout in sid.LAYOUTS
            if layout.max_id >= 42
        }
        self.assertEqual(len(set(encoded_by_layout.values())), len(encoded_by_layout))
        for (profile, mode), encoded in encoded_by_layout.items():
            result = sid.validate_hex(encoded)
            self.assertTrue(result.ok)
            self.assertEqual((result.profile, result.mode), (profile, mode))
            self.assertEqual(result.id, 42)

    def test_different_password_cannot_decode_existing_public_id(self) -> None:
        for layout in sid.LAYOUTS:
            encoded = self.assert_public_hex(123 if layout.max_id >= 123 else 1, profile=layout.profile, boosted=layout.boosted)
            with self.subTest(layout=f"{layout.profile}/{layout.mode}"):
                with patched_password(OTHER_TEST_PASSWORD):
                    self.assertIsNone(sid.hex_to_id(encoded))
                    self.assertFalse(sid.validate_hex(encoded).ok)

    def test_invalid_id_inputs_return_none(self) -> None:
        invalid_base_values = [
            None,
            True,
            False,
            0,
            -1,
            1.0,
            12.9,
            "12.0",
            "abc",
            " 12",
            "12 ",
            "+12",
            "-12",
            "",
            "1_000",
            b"12",
            [],
            {},
            object(),
            "9" * 1000,
        ]
        invalid_profile_values = [None, True, False, 8, "", "uint7", "uint32 ", "int32", [], {}]
        invalid_boosted_values = [None, 0, 1, "false", "true", [], {}]

        for layout in sid.LAYOUTS:
            too_large = layout.max_id + 1
            for value in invalid_base_values + [too_large]:
                with self.subTest(layout=f"{layout.profile}/{layout.mode}", value=repr(value)):
                    self.assertIsNone(sid.id_to_hex(value, profile=layout.profile, boosted=layout.boosted))

        for profile in invalid_profile_values:
            with self.subTest(profile=repr(profile)):
                self.assertIsNone(sid.id_to_hex(1, profile=profile))
                self.assertIsNone(sid.layout_for_profile(profile))

        for boosted in invalid_boosted_values:
            with self.subTest(boosted=repr(boosted)):
                self.assertIsNone(sid.id_to_hex(1, boosted=boosted))
                self.assertIsNone(sid.layout_for_profile("uint32", boosted=boosted))

    def test_long_decimal_id_string_is_rejected_before_regex(self) -> None:
        class ExplodingRegex:
            def fullmatch(self, value: object) -> object:
                raise AssertionError(f"decimal regex should not inspect overlong value: {value!r}")

        with mock.patch.object(sid, "_DECIMAL_RE", ExplodingRegex()):
            self.assertIsNone(sid.id_to_hex("1" * 1000))
            self.assertIsNone(sid.id_to_hex(("0" * 1000) + "1"))

    def test_invalid_hex_inputs_return_none_and_real_validation_errors(self) -> None:
        cases = [
            (None, "not_string"),
            (True, "not_string"),
            (False, "not_string"),
            (0, "not_string"),
            (123, "not_string"),
            (b"0000000000000000", "not_string"),
            ("", "unsupported_length"),
            ("0", "unsupported_length"),
            ("0" * 15, "unsupported_length"),
            ("0" * 17, "unsupported_length"),
            ("g" * 16, "invalid_hex"),
            ("z" * 16, "invalid_hex"),
            (" " * 16, "invalid_hex"),
            ([], "not_string"),
            ({}, "not_string"),
            (object(), "not_string"),
        ]

        for value, code in cases:
            with self.subTest(value=repr(value)):
                self.assertIsNone(sid.hex_to_id(value))
                self.assertIsNone(sid.hex_to_parts(value))
                result = sid.validate_hex(value)
                self.assertFalse(result.ok)
                self.assertEqual(result.error_code, code)
                self.assertIsInstance(result.error, str)

    def test_unsupported_hex_length_is_rejected_before_regex_or_large_lowercase(self) -> None:
        class ExplodingRegex:
            def fullmatch(self, value: object) -> object:
                raise AssertionError(f"hex regex should not inspect unsupported length: {value!r}")

        class NoLowerString(str):
            def lower(self) -> str:
                raise AssertionError("overlong unsupported hex should not be lowercased")

        with mock.patch.object(sid, "_HEX_CHARS_RE", ExplodingRegex()):
            short_result = sid.validate_hex("g" * 15)
            self.assertFalse(short_result.ok)
            self.assertEqual(short_result.error_code, "unsupported_length")

            long_result = sid.validate_hex(NoLowerString("g" * 1000))
            self.assertFalse(long_result.ok)
            self.assertEqual(long_result.error_code, "unsupported_length")
            self.assertIsNone(long_result.public_hex)

    def test_all_zero_supported_lengths_are_rejected_with_validation_detail(self) -> None:
        # All-zero strings are syntactically well formed for every supported
        # length, but should not validate under the secret layout/tag checks.
        for hex_chars in sid.SUPPORTED_HEX_LENGTHS:
            value = "0" * hex_chars
            result = sid.validate_hex(value)
            with self.subTest(hex_chars=hex_chars, code=result.error_code):
                self.assertFalse(result.ok)
                self.assertIsNotNone(result.layout)
                self.assertIsNotNone(result.error_code)
                self.assertIn(result.error_code, {"unsupported_version", "tag_mismatch", "id_out_of_range"})
                self.assertIsNone(sid.hex_to_id(value))

    def test_single_nibble_tampering_is_rejected(self) -> None:
        for layout in sid.LAYOUTS:
            id_values = [1, layout.max_id]
            if layout.max_id >= 123:
                id_values.append(123)
            for id_value in id_values:
                encoded = self.assert_public_hex(id_value, profile=layout.profile, boosted=layout.boosted)
                for position, original in enumerate(encoded):
                    replacement = "0" if original != "0" else "1"
                    tampered = encoded[:position] + replacement + encoded[position + 1 :]
                    with self.subTest(layout=f"{layout.profile}/{layout.mode}", id_value=id_value, position=position):
                        self.assertIsNone(sid.hex_to_id(tampered))
                        self.assertFalse(sid.validate_hex(tampered).ok)

    def test_valid_tag_for_inactive_versions_is_rejected(self) -> None:
        for layout in sid.LAYOUTS:
            round_keys, tag_key = sid._key_material(layout)
            id_index = 0
            for inactive_version in [0, 2, 15]:
                with self.subTest(layout=f"{layout.profile}/{layout.mode}", inactive_version=inactive_version):
                    tag = sid._tag(inactive_version, id_index, tag_key, layout)
                    plain = (
                        (inactive_version << (layout.id_bits + layout.tag_bits))
                        | (id_index << layout.tag_bits)
                        | tag
                    )
                    encoded = f"{sid._feistel_encrypt(plain, round_keys, layout):0{layout.hex_chars}x}"

                    result = sid.validate_hex(encoded)
                    self.assertFalse(result.ok)
                    self.assertEqual(result.error_code, "unsupported_version")
                    self.assertIsNone(sid.hex_to_id(encoded))

    def test_valid_tag_for_unused_all_ones_id_slot_is_rejected(self) -> None:
        for layout in sid.LAYOUTS:
            round_keys, tag_key = sid._key_material(layout)
            version = sid.ISSUE_VERSION
            first_unused_id_index = layout.max_id
            tag = sid._tag(version, first_unused_id_index, tag_key, layout)
            plain = (
                (version << (layout.id_bits + layout.tag_bits))
                | (first_unused_id_index << layout.tag_bits)
                | tag
            )
            encoded = f"{sid._feistel_encrypt(plain, round_keys, layout):0{layout.hex_chars}x}"

            with self.subTest(layout=f"{layout.profile}/{layout.mode}"):
                result = sid.validate_hex(encoded)
                self.assertFalse(result.ok)
                self.assertEqual(result.error_code, "id_out_of_range")
                self.assertIsNone(sid.hex_to_id(encoded))

    def test_tag_mismatch_is_rejected(self) -> None:
        for layout in sid.LAYOUTS:
            encoded = self.assert_public_hex(1, profile=layout.profile, boosted=layout.boosted)
            round_keys, _tag_key = sid._key_material(layout)
            plain = sid._feistel_decrypt(int(encoded, 16), round_keys, layout)

            # Flip one bit in the compact tag field, then re-encrypt so the outer
            # Feistel layer is well-formed but the keyed tag is wrong.
            bad_plain = plain ^ 1
            bad_encoded = f"{sid._feistel_encrypt(bad_plain, round_keys, layout):0{layout.hex_chars}x}"

            with self.subTest(layout=f"{layout.profile}/{layout.mode}"):
                result = sid.validate_hex(bad_encoded)
                self.assertFalse(result.ok)
                self.assertEqual(result.error_code, "tag_mismatch")
                self.assertIsNone(sid.hex_to_id(bad_encoded))

    def test_private_pack_unpack_round_trip(self) -> None:
        for layout in sid.LAYOUTS:
            _round_keys, tag_key = sid._key_material(layout)
            id_values = [1, layout.max_id]
            if layout.max_id >= 123:
                id_values.append(123)
            for id_value in id_values:
                with self.subTest(layout=f"{layout.profile}/{layout.mode}", id_value=id_value):
                    id_index = id_value - 1
                    plain = sid._pack_plain(sid.ISSUE_VERSION, id_index, tag_key, layout)
                    version, unpacked_index, supplied_tag = sid._unpack_plain(plain, layout)
                    self.assertEqual(version, sid.ISSUE_VERSION)
                    self.assertEqual(unpacked_index, id_index)
                    self.assertTrue(sid._tags_equal(supplied_tag, sid._tag(sid.ISSUE_VERSION, id_index, tag_key, layout), layout))

    def test_default_private_compatibility_shaped_helpers(self) -> None:
        round_keys, tag_key = sid._key_material()
        plain64 = sid._pack_plain64(sid.ISSUE_VERSION, 0, tag_key)
        encrypted64 = sid._feistel_encrypt64(plain64, round_keys)
        self.assertEqual(sid._feistel_decrypt64(encrypted64, round_keys), plain64)
        self.assertEqual(sid._unpack_plain64(plain64)[0], sid.ISSUE_VERSION)
        self.assertTrue(sid._tags_equal(sid._tag28(sid.ISSUE_VERSION, 0, tag_key), sid._tag(sid.ISSUE_VERSION, 0, tag_key, sid.DEFAULT_LAYOUT)))

    def test_private_helpers_reject_out_of_range_values(self) -> None:
        for layout in sid.LAYOUTS:
            round_keys, tag_key = sid._key_material(layout)
            with self.subTest(layout=f"{layout.profile}/{layout.mode}"):
                with self.assertRaises(ValueError):
                    sid._pack_plain(-1, 0, tag_key, layout)
                with self.assertRaises(ValueError):
                    sid._pack_plain(16, 0, tag_key, layout)
                with self.assertRaises(ValueError):
                    sid._pack_plain(sid.ISSUE_VERSION, -1, tag_key, layout)
                with self.assertRaises(ValueError):
                    sid._pack_plain(sid.ISSUE_VERSION, layout.max_id, tag_key, layout)
                with self.assertRaises(ValueError):
                    sid._tag(16, 0, tag_key, layout)
                with self.assertRaises(ValueError):
                    sid._tag(sid.ISSUE_VERSION, 1 << layout.id_bits, tag_key, layout)
                with self.assertRaises(ValueError):
                    sid._feistel_encrypt(-1, round_keys, layout)
                with self.assertRaises(ValueError):
                    sid._feistel_decrypt(1 << layout.total_bits, round_keys, layout)
                with self.assertRaises(ValueError):
                    sid._unpack_plain(1 << layout.total_bits, layout)

    def test_feistel_permutation_inverse_on_representative_values(self) -> None:
        for layout in sid.LAYOUTS:
            round_keys, tag_key = sid._key_material(layout)
            representatives = [
                0,
                1,
                (1 << layout.half_bits) - 1,
                1 << layout.half_bits,
                sid._pack_plain(sid.ISSUE_VERSION, 0, tag_key, layout),
                sid._pack_plain(sid.ISSUE_VERSION, layout.max_id - 1, tag_key, layout),
                (1 << layout.total_bits) - 1,
            ]

            encrypted_values = set()
            for value in representatives:
                with self.subTest(layout=f"{layout.profile}/{layout.mode}", value=value):
                    encrypted = sid._feistel_encrypt(value, round_keys, layout)
                    self.assertNotIn(encrypted, encrypted_values)
                    encrypted_values.add(encrypted)
                    self.assertEqual(sid._feistel_decrypt(encrypted, round_keys, layout), value)

    def test_no_collisions_for_sequential_smoke_sample(self) -> None:
        for layout in sid.LAYOUTS:
            sample_size = min(500, layout.max_id)
            seen: set[str] = set()
            for id_value in range(1, sample_size + 1):
                with self.subTest(layout=f"{layout.profile}/{layout.mode}", id_value=id_value):
                    encoded = sid.id_to_hex(id_value, profile=layout.profile, boosted=layout.boosted)
                    self.assertIsNotNone(encoded)
                    assert encoded is not None
                    self.assertNotIn(encoded, seen)
                    seen.add(encoded)
                    self.assertEqual(sid.hex_to_id(encoded), id_value)

    def test_security_math_for_normal_and_boosted_profiles(self) -> None:
        guesses_per_year = 10 * 2 * 24 * 365
        self.assertEqual(guesses_per_year, 175_200)
        normal_worst_case_years = (1 << 32) / guesses_per_year
        boosted_min_worst_case_years = (1 << 64) / guesses_per_year
        self.assertAlmostEqual(normal_worst_case_years, 24_515, delta=1)
        self.assertAlmostEqual(boosted_min_worst_case_years, 105_289_635_123_913, delta=1_000_000)

        for layout in sid.LAYOUTS:
            exact_probability = layout.max_id / (1 << layout.total_bits)
            approximate_exponent = layout.version_bits + layout.tag_bits
            with self.subTest(layout=f"{layout.profile}/{layout.mode}"):
                self.assertEqual(layout.random_valid_probability, exact_probability)
                # Exact integer checks avoid float rounding at uint64 scale.
                self.assertLess(layout.max_id * (1 << approximate_exponent), 1 << layout.total_bits)
                self.assertGreater(
                    layout.max_id * 100 * (1 << approximate_exponent),
                    99 * (1 << layout.total_bits),
                )
                if layout.mode == "normal":
                    self.assertEqual(approximate_exponent, 32)
                else:
                    self.assertGreaterEqual(approximate_exponent, 64)

        self.assertIn("24_515 years", sid.__doc__ or "")
        self.assertIn("105_289_635_123_913 years", sid.__doc__ or "")
        self.assertIn("175_200 guesses", sid.__doc__ or "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
