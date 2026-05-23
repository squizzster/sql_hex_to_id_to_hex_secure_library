#!/usr/bin/env python3
"""Tests for sql_id_library.py.

Run with:
    python -m pytest

The tests set safe default test hex key material and a per-test pepper file,
then also cover missing, weak, low-diversity, low-bit-balance, wrong-secret,
wrong-salt, and wrong-pepper behavior.
"""

from __future__ import annotations

import os
import re
import tempfile
import unittest
import builtins
from contextlib import contextmanager
from pathlib import Path
from unittest import mock


TEST_PASSWORD = "00112233445566778899aabbccddeeff" * 2
OTHER_TEST_PASSWORD = "ffeeddccbbaa99887766554433221100" * 2
TEST_DOMAIN_SALT_HEX = "0b91b4e8fd74bcb256a19d188c83470a7b75a4897babb252e54b6eb8f8bb392d"
OTHER_TEST_DOMAIN_SALT_HEX = "1234567890abcdef" * 4
TEST_PEPPER_HEX = "0123456789abcdef" * 4
OTHER_TEST_PEPPER_HEX = "fedcba9876543210" * 4
LOW_BIT_BALANCE_HEX = "0102040810204080" * 4
DEMO_LABELS = {
    "dry_run": 1,
    "plan": 2,
    "execute": 3,
    "enquire": 4,
    "repair": 5,
}
PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_CONF_DIR = PROJECT_ROOT / "conf"
os.environ["SQL_ID_LIBRARY_PASSWORD_HEX_v1"] = TEST_PASSWORD
os.environ["SQL_ID_LIBRARY_DOMAIN_SALT_HEX_v1"] = TEST_DOMAIN_SALT_HEX

import sql_id_library as sid  # noqa: E402  - env default is set before import


@contextmanager
def patched_env_var(name: str, value: str | None):
    """Temporarily patch one environment variable."""
    old_present = name in os.environ
    old_value = os.environ.get(name)
    try:
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
        yield
    finally:
        if old_present and old_value is not None:
            os.environ[name] = old_value
        else:
            os.environ.pop(name, None)


def write_test_pepper(path: Path, value: str = TEST_PEPPER_HEX, mode: int = 0o400, *, newline: bool = True) -> None:
    """Write a test pepper file with intentionally narrow permissions."""
    path.unlink(missing_ok=True)
    path.write_text(value + ("\n" if newline else ""), encoding="ascii")
    path.chmod(mode)


@contextmanager
def patched_password(value: str | None):
    """Temporarily patch the v1 SQL ID password for tests."""
    with patched_env_var(sid.ENV_PASSWORD_NAME, value):
        yield


@contextmanager
def patched_labels(labels: dict[str, int]):
    """Temporarily patch the local label-name registry."""
    old_labels = sid.available_labels()
    try:
        sid.configure_sql_id({"labels": labels})
        yield
    finally:
        sid.configure_sql_id({"labels": old_labels})


class TestSqlIdLibrary(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory(prefix="sql_id_library_test_")
        self.addCleanup(self._temp_dir.cleanup)
        self.test_dir = Path(self._temp_dir.name)
        self.test_pepper_path = self.test_dir / "test_sql_id_pepper_v1.key"

        os.environ[sid.ENV_PASSWORD_NAME] = TEST_PASSWORD
        os.environ[sid.ENV_DOMAIN_SALT_NAME] = TEST_DOMAIN_SALT_HEX
        write_test_pepper(self.test_pepper_path)
        sid.clear_sql_id_config()
        sid.configure_sql_id({"pepper_file_location": str(self.test_pepper_path)})

    def tearDown(self) -> None:
        self.test_pepper_path.chmod(0o600) if self.test_pepper_path.exists() else None
        self.test_pepper_path.unlink(missing_ok=True)

    def assert_public_hex(self, encoded: object) -> str:
        self.assertIsInstance(encoded, str)
        assert encoded is not None
        self.assertRegex(encoded, re.compile(rf"^[0-9a-f]{{{sid.HEX_CHARS}}}$"))
        return encoded

    def test_fixed_layout_uses_full_128_bit_budget(self) -> None:
        layout = sid.DEFAULT_LAYOUT

        self.assertEqual(sid.SCHEME_REVISION, 4)
        self.assertEqual(sid.VERSION_BITS, 3)
        self.assertEqual(sid.LABEL_BITS, 5)
        self.assertEqual(sid.RANGE_BITS, 1)
        self.assertEqual(sid.SMALL_ID_BITS, 32)
        self.assertEqual(sid.BIGINT_ID_BITS, 64)
        self.assertEqual(sid.MAX_ID_BITS, 64)
        self.assertEqual(sid.SMALL_TAG_BITS, 87)
        self.assertEqual(sid.BIGINT_TAG_BITS, 55)
        self.assertEqual(sid.MIN_TAG_BITS, 55)
        self.assertEqual(sid.MAX_TAG_BITS, 87)
        self.assertEqual(sid.TOTAL_BITS, 128)
        self.assertEqual(sid.HEX_CHARS, 32)
        self.assertEqual(sid.SUPPORTED_HEX_LENGTHS, (32,))
        self.assertEqual(sid.ENV_PASSWORD_BASE_NAME, "SQL_ID_LIBRARY_PASSWORD_HEX")
        self.assertEqual(sid.ENV_DOMAIN_SALT_BASE_NAME, "SQL_ID_LIBRARY_DOMAIN_SALT_HEX")
        self.assertEqual(sid.ENV_PASSWORD_NAME, "SQL_ID_LIBRARY_PASSWORD_HEX_v1")
        self.assertEqual(sid.ENV_DOMAIN_SALT_NAME, "SQL_ID_LIBRARY_DOMAIN_SALT_HEX_v1")
        self.assertEqual(sid.MIN_VERSION, 1)
        self.assertEqual(sid.MAX_VERSION, 6)
        self.assertEqual(sid.ISSUE_VERSION, 1)
        self.assertEqual(sid.ACTIVE_DECODE_VERSIONS, frozenset(range(1, 7)))
        self.assertEqual(sid.DEFAULT_ALLOWED_VERSIONS, frozenset(range(1, 7)))
        self.assertEqual(sid.allowed_versions(), (1, 2, 3, 4, 5, 6))
        self.assertEqual(sid.configured_issue_version(), 1)
        self.assertEqual(sid.RESERVED_VERSION, 7)
        self.assertEqual(sid.NO_LABEL, 0)
        self.assertEqual(sid.MAX_LABEL, 30)
        self.assertEqual(sid.RESERVED_LABEL, 31)
        self.assertEqual(sid.SMALL_RANGE_CLASS, 0)
        self.assertEqual(sid.BIGINT_RANGE_CLASS, 1)
        self.assertEqual(sid.SMALL_RANGE_MAX_ID, 4_294_967_295)
        self.assertEqual(sid.BIGINT_RANGE_MIN_ID, 4_294_967_296)
        self.assertEqual(sid.MAX_ID, 18_446_744_073_709_551_615)
        self.assertEqual(sid.MYSQL_UNSIGNED_BIGINT_MAX, sid.MAX_ID)
        self.assertEqual(sid.MIN_KEY_INPUT_HEX_CHARS, 64)
        self.assertEqual(sid.MAX_KEY_INPUT_HEX_CHARS, 512)
        self.assertEqual(sid.MIN_KEY_INPUT_BYTES, 32)
        self.assertEqual(sid.MAX_KEY_INPUT_BYTES, 256)
        self.assertEqual(sid.MIN_KEY_INPUT_UNIQUE_BYTES, 8)
        self.assertEqual(sid.KEY_INPUT_BIT_BALANCE_MIN_TAIL_PROBABILITY, 1e-12)
        self.assertEqual(sid.NORMALIZED_KEY_INPUT_BYTES, 64)
        self.assertEqual(sid.MIN_PASSWORD_HEX_CHARS, 64)
        self.assertEqual(sid.MAX_PASSWORD_HEX_CHARS, 512)
        self.assertEqual(sid.MIN_PASSWORD_BYTES, 32)
        self.assertEqual(sid.MAX_PASSWORD_BYTES, 256)
        self.assertEqual(sid.DEFAULT_PEPPER_FILE_LOCATION, "~/.sql_hex_id_pepper_file_v1.key")
        self.assertEqual(sid.MIN_PEPPER_HEX_CHARS, 64)
        self.assertEqual(sid.MAX_PEPPER_HEX_CHARS, 512)
        self.assertEqual(sid.MIN_PEPPER_BYTES, 32)
        self.assertEqual(sid.MAX_PEPPER_BYTES, 256)
        self.assertEqual(sid.configured_pepper_file_location(), str(self.test_pepper_path))
        self.assertGreaterEqual(sid.ROUNDS, 12)
        self.assertEqual(sid.MIN_DOMAIN_SALT_HEX_CHARS, 64)
        self.assertEqual(sid.MAX_DOMAIN_SALT_HEX_CHARS, 512)
        self.assertEqual(sid.MIN_DOMAIN_SALT_BYTES, 32)
        self.assertEqual(sid.MAX_DOMAIN_SALT_BYTES, 256)
        self.assertEqual(sid.MIN_DOMAIN_SALT_UNIQUE_BYTES, 8)
        self.assertTrue(sid._constants_are_sane())

        self.assertEqual(layout.header_bits + sid.SMALL_ID_BITS + sid.SMALL_TAG_BITS, 128)
        self.assertEqual(layout.header_bits + sid.BIGINT_ID_BITS + sid.BIGINT_TAG_BITS, 128)
        self.assertEqual(layout.bytes, 16)
        self.assertEqual(layout.half_bits, 64)
        self.assertEqual(layout.hex_chars, 32)
        self.assertEqual(layout.max_id, (1 << 64) - 1)
        self.assertEqual(layout.valid_id_count, sid.MAX_ID)
        self.assertEqual(layout.id_states, 1 << 64)
        self.assertEqual(layout.version_mask, sid.RESERVED_VERSION)
        self.assertEqual(layout.label_mask, sid.RESERVED_LABEL)
        self.assertEqual(layout.range_mask, 1)
        self.assertEqual(layout.range_for_id(1), sid.SMALL_RANGE_LAYOUT)
        self.assertEqual(layout.range_for_id(sid.SMALL_RANGE_MAX_ID), sid.SMALL_RANGE_LAYOUT)
        self.assertEqual(layout.range_for_id(sid.BIGINT_RANGE_MIN_ID), sid.BIGINT_RANGE_LAYOUT)
        self.assertEqual(layout.range_for_id(sid.MAX_ID), sid.BIGINT_RANGE_LAYOUT)
        self.assertIs(sid.layout_for_hex_length(32), sid.DEFAULT_LAYOUT)
        self.assertIsNone(sid.layout_for_hex_length(16))
        self.assertIsNone(sid.layout_for_hex_length(31))
        self.assertIsNone(sid.layout_for_hex_length(True))

    def test_key_input_bit_balance_cutoffs_are_length_aware(self) -> None:
        cutoffs = [
            (256, 71, 72),
            (512, 175, 176),
            (1024, 397, 398),
            (2048, 862, 863),
        ]
        for n_bits, rejected_low_ones, accepted_low_ones in cutoffs:
            with self.subTest(n_bits=n_bits):
                self.assertLessEqual(
                    sid._binomial_two_sided_tail_probability(n_bits, rejected_low_ones),
                    sid.KEY_INPUT_BIT_BALANCE_MIN_TAIL_PROBABILITY,
                )
                self.assertGreater(
                    sid._binomial_two_sided_tail_probability(n_bits, accepted_low_ones),
                    sid.KEY_INPUT_BIT_BALANCE_MIN_TAIL_PROBABILITY,
                )

    def test_key_inputs_are_sanity_checked_then_normalized_to_sha512(self) -> None:
        self.assertEqual(len(sid._password_bytes()), sid.NORMALIZED_KEY_INPUT_BYTES)
        self.assertEqual(len(sid._domain_salt_bytes()), sid.NORMALIZED_KEY_INPUT_BYTES)
        self.assertEqual(len(sid._pepper_bytes()), sid.NORMALIZED_KEY_INPUT_BYTES)
        self.assertNotEqual(sid._password_bytes(), bytes.fromhex(TEST_PASSWORD))
        self.assertNotEqual(sid._pepper_bytes(), bytes.fromhex(TEST_PEPPER_HEX))

        with patched_password("00112233445566778899aabbccddeeff" * 16):
            self.assertEqual(len(sid._password_bytes()), sid.NORMALIZED_KEY_INPUT_BYTES)
            self.assertTrue(sid.is_configured())

    def test_key_input_bit_balance_rejects_extreme_manual_values(self) -> None:
        with patched_password(LOW_BIT_BALANCE_HEX):
            self.assertFalse(sid.is_configured())
            result = sid.validate_hex("0" * sid.HEX_CHARS)
            self.assertFalse(result.ok)
            self.assertEqual(result.error_code, "bad_config")
            self.assertIn("bit balance", result.error or "")

        with patched_env_var(sid.ENV_DOMAIN_SALT_NAME, LOW_BIT_BALANCE_HEX):
            self.assertFalse(sid.is_configured())
            result = sid.validate_hex("0" * sid.HEX_CHARS)
            self.assertFalse(result.ok)
            self.assertEqual(result.error_code, "bad_config")
            self.assertIn(f"{sid.ENV_DOMAIN_SALT_NAME} bit balance", result.error or "")

        pepper_path = self.test_dir / "low_bit_balance_sql_id_pepper_v1.key"
        write_test_pepper(pepper_path, LOW_BIT_BALANCE_HEX)
        try:
            sid.configure_sql_id({"pepper_file_location": str(pepper_path)})
            self.assertFalse(sid.is_configured())
            result = sid.validate_hex("0" * sid.HEX_CHARS)
            self.assertFalse(result.ok)
            self.assertEqual(result.error_code, "low_bit_balance_pepper")
            self.assertIn("bit balance", result.error or "")
        finally:
            pepper_path.chmod(0o600) if pepper_path.exists() else None
            pepper_path.unlink(missing_ok=True)
            sid.configure_sql_id({"pepper_file_location": str(self.test_pepper_path)})

    def test_unlabeled_public_api_round_trips_edges_and_representatives(self) -> None:
        values: list[object] = [
            1,
            2,
            12,
            999,
            "1",
            "000001",
            sid.SMALL_RANGE_MAX_ID - 1,
            sid.SMALL_RANGE_MAX_ID,
            sid.BIGINT_RANGE_MIN_ID,
            sid.MAX_ID - 1,
            sid.MAX_ID,
            str(sid.MAX_ID),
        ]
        for value in values:
            with self.subTest(value=value):
                expected = int(value)
                encoded = self.assert_public_hex(sid.id_to_hex(value))
                self.assertEqual(len(encoded), 32)
                self.assertEqual(sid.hex_to_id(encoded), expected)
                self.assertEqual(sid.hex_to_id(encoded.upper()), expected)
                self.assertEqual(sid.sql_decode_id(encoded), expected)

                result = sid.validate_hex(encoded)
                self.assertTrue(result.ok)
                self.assertEqual(result.id, expected)
                self.assertEqual(result.label_id, sid.NO_LABEL)
                self.assertIsNone(result.label)
                self.assertEqual(
                    result.range_class,
                    sid.SMALL_RANGE_CLASS if expected <= sid.SMALL_RANGE_MAX_ID else sid.BIGINT_RANGE_CLASS,
                )
                self.assertEqual(
                    result.tag_bits,
                    sid.SMALL_TAG_BITS if expected <= sid.SMALL_RANGE_MAX_ID else sid.BIGINT_TAG_BITS,
                )
                self.assertEqual(result.version, sid.ISSUE_VERSION)
                self.assertIsNone(result.error)
                self.assertIsNone(result.error_code)
                self.assertEqual(
                    sid.hex_to_parts(encoded),
                    (
                        sid.NO_LABEL,
                        None,
                        sid.SMALL_RANGE_CLASS if expected <= sid.SMALL_RANGE_MAX_ID else sid.BIGINT_RANGE_CLASS,
                        sid.SMALL_TAG_BITS if expected <= sid.SMALL_RANGE_MAX_ID else sid.BIGINT_TAG_BITS,
                        sid.ISSUE_VERSION,
                        expected,
                    ),
                )

    def test_golden_vectors_lock_public_id_format(self) -> None:
        self.assertEqual(os.environ.get(sid.ENV_PASSWORD_NAME), TEST_PASSWORD)
        self.assertEqual(TEST_PASSWORD, "00112233445566778899aabbccddeeff" * 2)
        self.assertEqual(os.environ.get(sid.ENV_DOMAIN_SALT_NAME), TEST_DOMAIN_SALT_HEX)
        self.assertEqual(TEST_PEPPER_HEX, "0123456789abcdef" * 4)

        plain_vectors = [
            (1, "ffe221b73c4434daa0799d97c47f8dcc"),
            (sid.SMALL_RANGE_MAX_ID, "700dd08b0c32476c5bcb8315504e5b68"),
            (sid.BIGINT_RANGE_MIN_ID, "d1fc0dd1b57e795242650b48ad128818"),
            (sid.MAX_ID, "dcff9210506f5e0a266eaa1a7183bd86"),
        ]
        for id_value, expected_hex in plain_vectors:
            with self.subTest(id_value=id_value):
                self.assertEqual(sid.id_to_hex(id_value), expected_hex)
                self.assertEqual(sid.hex_to_id(expected_hex), id_value)
                result = sid.validate_hex(expected_hex)
                self.assertTrue(result.ok)
                self.assertEqual(result.id, id_value)
                self.assertEqual(result.label_id, sid.NO_LABEL)

        with patched_labels(DEMO_LABELS):
            labeled_vectors = [
                ("dry_run", 1, "8b99f28a77cac023c1f15a23db28e94a"),
                ("plan", 1, "683f6eefac70e5e8633d3c9ecebcf412"),
                ("repair", 1, "031a6b14ff600bf3cf463f00e9658788"),
            ]
            for label, id_value, expected_hex in labeled_vectors:
                with self.subTest(label=label, id_value=id_value):
                    self.assertEqual(sid.id_to_hex_label(id_value, label), expected_hex)
                    self.assertEqual(sid.hex_to_id_label(expected_hex, label), id_value)
                    self.assertIsNone(sid.hex_to_id(expected_hex))

                    result = sid.validate_hex_label(expected_hex, label)
                    self.assertTrue(result.ok)
                    self.assertEqual(result.id, id_value)
                    self.assertEqual(result.label_id, DEMO_LABELS[label])
                    self.assertEqual(result.label, label)

            repair_hex = "031a6b14ff600bf3cf463f00e9658788"
            self.assertIsNone(sid.hex_to_id(repair_hex))
            self.assertIsNone(sid.hex_to_id_label(repair_hex, "plan"))
            self.assertEqual(sid.hex_to_id_label(repair_hex, "repair"), 1)

    def test_range_classes_are_canonical_and_use_expected_tag_space(self) -> None:
        round_keys, _tag_key = sid._key_material()
        cases = [
            (1, sid.SMALL_RANGE_CLASS, sid.SMALL_TAG_BITS),
            (sid.SMALL_RANGE_MAX_ID, sid.SMALL_RANGE_CLASS, sid.SMALL_TAG_BITS),
            (sid.BIGINT_RANGE_MIN_ID, sid.BIGINT_RANGE_CLASS, sid.BIGINT_TAG_BITS),
            (sid.MAX_ID, sid.BIGINT_RANGE_CLASS, sid.BIGINT_TAG_BITS),
        ]

        for id_value, expected_range_class, expected_tag_bits in cases:
            with self.subTest(id_value=id_value):
                encoded = self.assert_public_hex(sid.id_to_hex(id_value))
                plain = sid._feistel_decrypt(int(encoded, 16), round_keys)
                version, label_id, range_class, unpacked_id, supplied_tag = sid._unpack_plain(plain)
                range_layout = sid.DEFAULT_LAYOUT.range_for_class(range_class)

                self.assertEqual(version, sid.ISSUE_VERSION)
                self.assertEqual(label_id, sid.NO_LABEL)
                self.assertEqual(range_class, expected_range_class)
                self.assertEqual(unpacked_id, id_value)
                self.assertLessEqual(supplied_tag, range_layout.tag_mask)
                self.assertEqual(range_layout.tag_bits, expected_tag_bits)

    def test_labeled_public_api_round_trips_with_int_and_configured_names(self) -> None:
        with patched_labels({"users": 1, "plans": 2, "repair": 30}):
            cases: list[tuple[object, int]] = [(1, 1), ("users", 1), ("PLANS", 2), ("repair", 30), (30, 30)]
            label_names_by_id = {1: "users", 2: "plans", 30: "repair"}
            for label, expected_label_id in cases:
                with self.subTest(label=label):
                    encoded = self.assert_public_hex(sid.id_to_hex_label(123, label))
                    self.assertEqual(sid.hex_to_id_label(encoded, label), 123)
                    self.assertEqual(sid.sql_decode_id_label(encoded, label), 123)
                    self.assertIsNone(sid.hex_to_id(encoded))

                    strict = sid.validate_hex_label(encoded, label)
                    self.assertTrue(strict.ok)
                    self.assertEqual(strict.id, 123)
                    self.assertEqual(strict.label_id, expected_label_id)
                    self.assertEqual(strict.label, label_names_by_id[expected_label_id])

                    inspected = sid.inspect_hex(encoded)
                    self.assertTrue(inspected.ok)
                    self.assertEqual(inspected.id, 123)
                    self.assertEqual(inspected.label_id, expected_label_id)

    def test_type_separation_is_strict(self) -> None:
        with patched_labels({"users": 1, "plans": 2, "repair": 3}):
            plain = self.assert_public_hex(sid.id_to_hex(123))
            user = self.assert_public_hex(sid.id_to_hex_label(123, "users"))
            plan = self.assert_public_hex(sid.id_to_hex_label(123, "plans"))

            self.assertEqual(len({plain, user, plan}), 3)

            self.assertEqual(sid.hex_to_id(plain), 123)
            self.assertIsNone(sid.hex_to_id(user))
            self.assertIsNone(sid.hex_to_id(plan))

            self.assertEqual(sid.hex_to_id_label(user, "users"), 123)
            self.assertIsNone(sid.hex_to_id_label(user, "plans"))
            self.assertIsNone(sid.hex_to_id_label(plan, "users"))
            self.assertIsNone(sid.hex_to_id_label(plain, "users"))

            self.assertEqual(sid.validate_hex(user).error_code, "label_mismatch")
            self.assertEqual(sid.validate_hex_label(user, "plans").error_code, "label_mismatch")
            self.assertEqual(sid.validate_hex_label(plain, "users").error_code, "label_mismatch")

    def test_label_registry_validation(self) -> None:
        sid.configure_sql_id({"labels": {"users": 1, "Plans": 2}})
        self.assertEqual(sid.available_labels(), {"users": 1, "plans": 2})
        self.assertEqual(sid.hex_to_id_label(sid.id_to_hex_label(1, "users"), "users"), 1)
        copied = sid.available_labels()
        copied["evil"] = 30
        self.assertEqual(sid.available_labels(), {"users": 1, "plans": 2})

        invalid_registries: list[object] = [
            None,
            [],
            {"": 1},
            {"1bad": 1},
            {"bad-name": 1},
            {"bad name": 1},
            {"users": 0},
            {"users": 31},
            {"users": True},
            {"users": "1"},
            {"users": 1, "USERS": 2},
            {"users": 1, "plans": 1},
            {1: 1},
        ]
        for labels in invalid_registries:
            with self.subTest(labels=repr(labels)):
                with self.assertRaises(ValueError):
                    sid.configure_sql_id({"labels": labels})  # type: ignore[dict-item]
                self.assertEqual(sid.available_labels(), {"users": 1, "plans": 2})

    def test_allowed_versions_config_validation(self) -> None:
        sid.configure_sql_id({"allowed_versions": [1, 3, 6]})
        self.assertEqual(sid.allowed_versions(), (1, 3, 6))

        invalid_allowed_versions: list[object] = [
            None,
            "1",
            [],
            [0],
            [7],
            [1, 1],
            [True],
            ["1"],
            [1.0],
        ]
        for versions in invalid_allowed_versions:
            with self.subTest(versions=repr(versions)):
                with self.assertRaises(ValueError):
                    sid.configure_sql_id({"allowed_versions": versions})  # type: ignore[dict-item]
                self.assertEqual(sid.allowed_versions(), (1, 3, 6))

    def test_pepper_file_location_must_be_main_v1_filename(self) -> None:
        original_location = sid.configured_pepper_file_location()
        invalid_paths = [
            self.test_dir / "sql_id_pepper.key",
            self.test_dir / "sql_id_pepper_v1",
            self.test_dir / "sql_id_pepper_v2.key",
            self.test_dir / "sql_id_pepper_v7.key",
        ]
        for path in invalid_paths:
            with self.subTest(path=path.name):
                with self.assertRaises(ValueError):
                    sid.configure_sql_id({"pepper_file_location": str(path)})
                self.assertEqual(sid.configured_pepper_file_location(), original_location)

    def test_configure_sql_id_accepts_pepper_path_labels_or_both(self) -> None:
        other_pepper_path = self.test_dir / "other_test_sql_id_pepper_v1.key"
        write_test_pepper(other_pepper_path, OTHER_TEST_PEPPER_HEX)
        try:
            sid.configure_sql_id({"labels": {"users": 1}})
            self.assertEqual(sid.available_labels(), {"users": 1})
            self.assertEqual(sid.configured_pepper_file_location(), str(self.test_pepper_path))

            sid.configure_sql_id({"pepper_file_location": str(other_pepper_path)})
            self.assertEqual(sid.available_labels(), {"users": 1})
            self.assertEqual(sid.configured_pepper_file_location(), str(other_pepper_path))

            sid.configure_sql_id({"pepper_file_location": str(self.test_pepper_path), "labels": {"plans": 2}})
            self.assertEqual(sid.available_labels(), {"plans": 2})
            self.assertEqual(sid.configured_pepper_file_location(), str(self.test_pepper_path))
        finally:
            other_pepper_path.chmod(0o600) if other_pepper_path.exists() else None
            other_pepper_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_json_file(self) -> None:
        sid.load_sql_id_config_from_file(TEST_CONF_DIR / "test_sql_id_config.json")
        self.assertEqual(sid.allowed_versions(), (1, 2, 3, 4, 5, 6))
        self.assertEqual(
            sid.available_labels(),
            {
                "dry_run": 1,
                "plan": 2,
                "execute": 3,
                "enquire": 4,
                "repair": 5,
            },
        )
        encoded = self.assert_public_hex(sid.id_to_hex_label(123, "repair"))
        self.assertEqual(sid.hex_to_id_label(encoded, "repair"), 123)
        self.assertIsNone(sid.hex_to_id_label(encoded, "plan"))

    def test_load_sql_id_config_from_yaml_file_when_yaml_is_available(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML is not installed")

        sid.load_sql_id_config_from_file(TEST_CONF_DIR / "test_sql_id_config.yaml")
        self.assertEqual(sid.allowed_versions(), (1, 2, 3, 4, 5, 6))
        self.assertEqual(
            sid.available_labels(),
            {
                "dry_run": 1,
                "plan": 2,
                "execute": 3,
                "enquire": 4,
                "repair": 5,
            },
        )
        encoded = self.assert_public_hex(sid.id_to_hex_label(123, "execute"))
        self.assertEqual(sid.hex_to_id_label(encoded, "execute"), 123)
        self.assertIsNone(sid.hex_to_id_label(encoded, "repair"))

    def test_load_sql_id_config_from_file_uses_cache_until_explicit_reload(self) -> None:
        json_path = self.test_dir / "cached_sql_id_config.json"
        json_path.write_text('{"labels": {"dry_run": 1}}\n', encoding="utf-8")
        try:
            sid.load_sql_id_config_from_file(json_path)
            self.assertEqual(sid.available_labels(), {"dry_run": 1})

            json_path.write_text('{"labels": {"repair": 5}}\n', encoding="utf-8")
            sid.load_sql_id_config_from_file(json_path)
            self.assertEqual(sid.available_labels(), {"dry_run": 1})

            json_path.write_text("[1, 2, 3]\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                sid.reload_sql_id_config_from_file(json_path)
            self.assertEqual(sid.available_labels(), {"dry_run": 1})

            json_path.write_text('{"labels": {"repair": 5}}\n', encoding="utf-8")
            sid.reload_sql_id_config_from_file(json_path)
            self.assertEqual(sid.available_labels(), {"repair": 5})

            json_path.write_text('{"labels": {"execute": 3}}\n', encoding="utf-8")
            sid.load_sql_id_config_from_file(json_path)
            self.assertEqual(sid.available_labels(), {"repair": 5})

            sid.clear_sql_id_config()
            sid.configure_sql_id({"pepper_file_location": str(self.test_pepper_path)})
            json_path.write_text('{"labels": {"plan": 2}}\n', encoding="utf-8")
            sid.load_sql_id_config_from_file(json_path)
            self.assertEqual(sid.available_labels(), {"plan": 2})
        finally:
            json_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_file_can_set_pepper_location(self) -> None:
        json_path = self.test_dir / "pepper_path_sql_id_config.json"
        other_pepper_path = self.test_dir / "config_sql_id_pepper_v1.key"
        write_test_pepper(other_pepper_path, OTHER_TEST_PEPPER_HEX)
        json_path.write_text(
            '{"pepper_file_location": "' + str(other_pepper_path) + '", "labels": {"dry_run": 1}}\n',
            encoding="utf-8",
        )
        try:
            before = self.assert_public_hex(sid.id_to_hex(123))
            sid.load_sql_id_config_from_file(json_path)
            self.assertEqual(sid.available_labels(), {"dry_run": 1})
            self.assertEqual(sid.configured_pepper_file_location(), str(other_pepper_path))
            after = self.assert_public_hex(sid.id_to_hex(123))
            self.assertNotEqual(before, after)
        finally:
            json_path.unlink(missing_ok=True)
            other_pepper_path.chmod(0o600) if other_pepper_path.exists() else None
            other_pepper_path.unlink(missing_ok=True)

    def test_cached_label_files_share_same_stem_across_json_and_yaml_paths(self) -> None:
        json_path = self.test_dir / "same_stem_cached_labels.json"
        yaml_path = self.test_dir / "same_stem_cached_labels.yaml"
        json_path.write_text('{"labels": {"dry_run": 1}}\n', encoding="utf-8")
        yaml_path.write_text("labels:\n  1: dry_run\n", encoding="utf-8")
        try:
            sid.load_sql_id_config_from_file(json_path)
            self.assertEqual(sid.available_labels(), {"dry_run": 1})
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(self.test_dir / "same_stem_cached_labels.txt")

            json_path.write_text('{"labels": {"repair": 5}}\n', encoding="utf-8")
            yaml_path.write_text("labels:\n  5: repair\n", encoding="utf-8")
            sid.load_sql_id_config_from_file(yaml_path)
            self.assertEqual(sid.available_labels(), {"dry_run": 1})

            sid.reload_sql_id_config_from_file(yaml_path)
            self.assertEqual(sid.available_labels(), {"repair": 5})
        finally:
            json_path.unlink(missing_ok=True)
            yaml_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_file_rejects_bad_inputs(self) -> None:
        sid.configure_sql_id({"labels": {"users": 1}})
        bad_json_path = self.test_dir / "bad_sql_id_labels.json"
        bad_json_path.write_text("[1, 2, 3]", encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(bad_json_path)
            self.assertEqual(sid.available_labels(), {"users": 1})
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(self.test_dir / "missing.sqlid")
            self.assertEqual(sid.available_labels(), {"users": 1})
        finally:
            bad_json_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_file_rejects_symlink_loop_as_value_error(self) -> None:
        if os.name != "posix" or not hasattr(os, "symlink"):
            self.skipTest("POSIX symlink behavior only")

        sid.configure_sql_id({"labels": {"users": 1}})
        loop_path = self.test_dir / "loop_sql_id_labels.json"
        loop_path.unlink(missing_ok=True)
        loop_path.symlink_to(loop_path)
        try:
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(loop_path)
            self.assertEqual(sid.available_labels(), {"users": 1})
        finally:
            loop_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_json_rejects_duplicate_keys_and_names(self) -> None:
        duplicate_key_path = self.test_dir / "duplicate_key_sql_id_labels.json"
        duplicate_name_path = self.test_dir / "duplicate_name_sql_id_labels.json"
        duplicate_key_path.write_text('{"labels": {"plan": 1, "plan": 2}}\n', encoding="utf-8")
        duplicate_name_path.write_text('{"labels": {"1": "plan", "2": "PLAN"}}\n', encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(duplicate_key_path)
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(duplicate_name_path)
        finally:
            duplicate_key_path.unlink(missing_ok=True)
            duplicate_name_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_yaml_rejects_duplicate_keys_names_and_bool_keys(self) -> None:
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML is not installed")

        duplicate_key_path = self.test_dir / "duplicate_key_sql_id_labels.yaml"
        duplicate_name_path = self.test_dir / "duplicate_name_sql_id_labels.yaml"
        bool_key_path = self.test_dir / "bool_key_sql_id_labels.yaml"
        duplicate_key_path.write_text("labels:\n  1: dry_run\n  1: plan\n", encoding="utf-8")
        duplicate_name_path.write_text("labels:\n  1: plan\n  2: PLAN\n", encoding="utf-8")
        bool_key_path.write_text("labels:\n  true: dry_run\n", encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(duplicate_key_path)
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(duplicate_name_path)
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(bool_key_path)
        finally:
            duplicate_key_path.unlink(missing_ok=True)
            duplicate_name_path.unlink(missing_ok=True)
            bool_key_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_yaml_errors_when_yaml_dependency_is_missing(self) -> None:
        yaml_path = self.test_dir / "no_yaml_dependency_sql_id_labels.yaml"
        yaml_path.write_text("labels:\n  1: dry_run\n", encoding="utf-8")

        real_import = builtins.__import__

        def fake_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "yaml":
                raise ImportError("blocked for test")
            return real_import(name, *args, **kwargs)

        try:
            with mock.patch("builtins.__import__", side_effect=fake_import):
                with self.assertRaises(ValueError):
                    sid.load_sql_id_config_from_file(yaml_path)
        finally:
            yaml_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_file_requires_same_stem_files_to_match(self) -> None:
        json_path = self.test_dir / "mismatch_sql_id_labels.json"
        yaml_path = self.test_dir / "mismatch_sql_id_labels.yaml"
        json_path.write_text('{"labels": {"dry_run": 1, "plan": 2}}\n', encoding="utf-8")
        yaml_path.write_text("labels:\n  1: dry_run\n  2: execute\n", encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(json_path)
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(yaml_path)
        finally:
            json_path.unlink(missing_ok=True)
            yaml_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_file_rejects_files_over_2000_bytes(self) -> None:
        large_path = self.test_dir / "large_sql_id_labels.json"
        large_path.write_text(" " * 2001, encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(large_path)
        finally:
            large_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_file_accepts_exactly_2000_bytes(self) -> None:
        exact_path = self.test_dir / "exact_size_sql_id_labels.json"
        payload = '{"labels": {"dry_run": 1}}'
        exact_path.write_text(payload + (" " * (2000 - len(payload))), encoding="utf-8")
        try:
            sid.load_sql_id_config_from_file(exact_path)
            self.assertEqual(sid.available_labels(), {"dry_run": 1})
        finally:
            exact_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_file_expands_home(self) -> None:
        with mock.patch.dict(os.environ, {"HOME": str(PROJECT_ROOT)}):
            sid.load_sql_id_config_from_file("~/conf/test_sql_id_config.json")
        self.assertEqual(
            sid.available_labels(),
            {
                "dry_run": 1,
                "plan": 2,
                "execute": 3,
                "enquire": 4,
                "repair": 5,
            },
        )

    def test_invalid_label_inputs_fail_closed(self) -> None:
        public_hex = self.assert_public_hex(sid.id_to_hex_label(1, 1))
        invalid_labels = [None, True, False, 0, 31, 32, -1, "", "unknown", "1", "bad-name", [], {}, object()]

        for label in invalid_labels:
            with self.subTest(label=repr(label)):
                self.assertIsNone(sid.id_to_hex_label(1, label))
                self.assertIsNone(sid.hex_to_id_label(public_hex, label))
                self.assertFalse(sid.validate_hex_label(public_hex, label).ok)

    def test_configuration_probe_and_config_errors(self) -> None:
        self.assertTrue(sid.is_configured())

        with patched_password(None):
            self.assertFalse(sid.is_configured())
            self.assertIsNone(sid.id_to_hex(1))
            result = sid.validate_hex("0" * sid.HEX_CHARS)
            self.assertFalse(result.ok)
            self.assertEqual(result.error_code, "bad_config")
            self.assertIsNone(sid.hex_to_id("0" * sid.HEX_CHARS))

        bad_passwords = [
            "short",
            "a" * (sid.MIN_PASSWORD_HEX_CHARS - 2),
            "0" * (sid.MIN_PASSWORD_HEX_CHARS + 1),
            "g" * sid.MIN_PASSWORD_HEX_CHARS,
            "00" * sid.MIN_PASSWORD_BYTES,
            "01" * (sid.MAX_PASSWORD_BYTES + 1),
        ]
        for bad_password in bad_passwords:
            with self.subTest(password=bad_password[:16]):
                with patched_password(bad_password):
                    self.assertFalse(sid.is_configured())
                    self.assertIsNone(sid.id_to_hex(1))
                    self.assertEqual(sid.validate_hex("0" * sid.HEX_CHARS).error_code, "bad_config")

        with patched_password("0123456789abcdef" * 4):
            self.assertTrue(sid.is_configured())
            self.assertIsNotNone(sid.id_to_hex(1))

        with patched_password("00112233445566778899aabbccddeeff" * 16):
            self.assertTrue(sid.is_configured())
            self.assertIsNotNone(sid.id_to_hex(1))

    def test_domain_salt_env_is_required(self) -> None:
        self.assertTrue(sid.is_configured())

        with patched_env_var(sid.ENV_DOMAIN_SALT_NAME, None):
            self.assertFalse(sid.is_configured())
            self.assertIsNone(sid.id_to_hex(1))
            result = sid.validate_hex("0" * sid.HEX_CHARS)
            self.assertFalse(result.ok)
            self.assertEqual(result.error_code, "bad_config")
            self.assertIn(sid.ENV_DOMAIN_SALT_NAME, result.error or "")

            missing_pepper_path = self.test_dir / "missing_for_salt_order_v1.key"
            missing_pepper_path.unlink(missing_ok=True)
            sid.configure_sql_id({"pepper_file_location": str(missing_pepper_path)})
            result = sid.validate_hex("0" * sid.HEX_CHARS)
            self.assertFalse(result.ok)
            self.assertEqual(result.error_code, "bad_config")
            self.assertIn(sid.ENV_DOMAIN_SALT_NAME, result.error or "")
            sid.configure_sql_id({"pepper_file_location": str(self.test_pepper_path)})

    def test_domain_salt_env_changes_key_material(self) -> None:
        first = self.assert_public_hex(sid.id_to_hex(1))

        with patched_env_var(sid.ENV_DOMAIN_SALT_NAME, OTHER_TEST_DOMAIN_SALT_HEX):
            self.assertTrue(sid.is_configured())
            second = self.assert_public_hex(sid.id_to_hex(1))
            self.assertNotEqual(second, first)
            self.assertEqual(sid.hex_to_id(second), 1)
            self.assertIsNone(sid.hex_to_id(first))

        self.assertEqual(sid.hex_to_id(first), 1)

    def test_domain_salt_env_is_strictly_validated(self) -> None:
        bad_env_salts = [
            "short",
            "0" * (sid.MIN_DOMAIN_SALT_HEX_CHARS + 1),
            "g" * sid.MIN_DOMAIN_SALT_HEX_CHARS,
            "00" * sid.MIN_DOMAIN_SALT_BYTES,
            LOW_BIT_BALANCE_HEX,
        ]
        for bad_salt in bad_env_salts:
            with self.subTest(salt=bad_salt[:16]):
                with patched_env_var(sid.ENV_DOMAIN_SALT_NAME, bad_salt):
                    self.assertFalse(sid.is_configured())
                    self.assertIsNone(sid.id_to_hex(1))
                    result = sid.validate_hex("0" * sid.HEX_CHARS)
                    self.assertFalse(result.ok)
                    self.assertEqual(result.error_code, "bad_config")
                    self.assertIn(sid.ENV_DOMAIN_SALT_NAME, result.error or "")

    def test_pepper_file_config_errors_are_specific(self) -> None:
        cases = [
            ("missing_sql_id_pepper_v1.key", None, None, "missing_pepper_file"),
            ("short_sql_id_pepper_v1.key", "0123456789abcdef", 0o400, "pepper_too_short"),
            ("long_sql_id_pepper_v1.key", "01" * (sid.MAX_PEPPER_BYTES + 1), 0o400, "pepper_too_long"),
            ("odd_sql_id_pepper_v1.key", ("01" * 32) + "0", 0o400, "invalid_pepper_hex"),
            ("nonhex_sql_id_pepper_v1.key", "g" * 64, 0o400, "invalid_pepper_hex"),
            ("leading_space_sql_id_pepper_v1.key", " " + TEST_PEPPER_HEX, 0o400, "invalid_pepper_hex"),
            ("trailing_space_sql_id_pepper_v1.key", TEST_PEPPER_HEX + " ", 0o400, "invalid_pepper_hex"),
            ("trailing_tab_sql_id_pepper_v1.key", TEST_PEPPER_HEX + "\t", 0o400, "invalid_pepper_hex"),
            ("low_diversity_sql_id_pepper_v1.key", "00" * 32, 0o400, "low_diversity_pepper"),
            ("world_readable_sql_id_pepper_v1.key", TEST_PEPPER_HEX, 0o644, "bad_pepper_permissions"),
        ]

        for filename, contents, mode, code in cases:
            pepper_path = self.test_dir / filename
            pepper_path.unlink(missing_ok=True)
            if contents is not None and mode is not None:
                write_test_pepper(pepper_path, contents, mode)
            try:
                sid.configure_sql_id({"pepper_file_location": str(pepper_path)})
                self.assertFalse(sid.is_configured(), code)
                self.assertIsNone(sid.id_to_hex(1))
                self.assertEqual(sid.validate_hex("0" * sid.HEX_CHARS).error_code, code)
            finally:
                pepper_path.chmod(0o600) if pepper_path.exists() else None
                pepper_path.unlink(missing_ok=True)
                sid.configure_sql_id({"pepper_file_location": str(self.test_pepper_path)})

    def test_pepper_file_accepts_exact_max_hex_and_rejects_larger_file(self) -> None:
        pepper_path = self.test_dir / "max_size_sql_id_pepper_v1.key"
        max_pepper_hex = "00112233445566778899aabbccddeeff" * 16
        try:
            write_test_pepper(pepper_path, max_pepper_hex, newline=False)
            sid.configure_sql_id({"pepper_file_location": str(pepper_path)})
            self.assertTrue(sid.is_configured())
            self.assertIsNotNone(sid.id_to_hex(1))

            write_test_pepper(pepper_path, max_pepper_hex, newline=True)
            sid.reload_sql_id_pepper()
            self.fail("expected max pepper plus newline to be rejected")
        except sid._ConfigError as exc:
            self.assertEqual(exc.code, "pepper_too_long")
        finally:
            pepper_path.chmod(0o600) if pepper_path.exists() else None
            pepper_path.unlink(missing_ok=True)
            sid.configure_sql_id({"pepper_file_location": str(self.test_pepper_path)})
            sid.reload_sql_id_pepper()

    def test_pepper_file_symlink_is_rejected(self) -> None:
        if os.name != "posix" or not hasattr(os, "symlink"):
            self.skipTest("POSIX symlink behavior only")

        target_path = self.test_dir / "target_sql_id_pepper_v1.key"
        symlink_path = self.test_dir / "symlink_sql_id_pepper_v1.key"
        write_test_pepper(target_path, TEST_PEPPER_HEX)
        symlink_path.unlink(missing_ok=True)
        symlink_path.symlink_to(target_path)
        try:
            sid.configure_sql_id({"pepper_file_location": str(symlink_path)})
            self.assertFalse(sid.is_configured())
            self.assertIsNone(sid.id_to_hex(1))
            self.assertEqual(sid.validate_hex("0" * sid.HEX_CHARS).error_code, "bad_pepper_file")
        finally:
            symlink_path.unlink(missing_ok=True)
            target_path.chmod(0o600) if target_path.exists() else None
            target_path.unlink(missing_ok=True)
            sid.configure_sql_id({"pepper_file_location": str(self.test_pepper_path)})

    def test_pepper_file_symlink_loop_is_rejected_with_specific_error(self) -> None:
        if os.name != "posix" or not hasattr(os, "symlink"):
            self.skipTest("POSIX symlink behavior only")

        loop_path = self.test_dir / "loop_sql_id_pepper_v1.key"
        loop_path.unlink(missing_ok=True)
        loop_path.symlink_to(loop_path)
        try:
            sid.configure_sql_id({"pepper_file_location": str(loop_path)})
            self.assertFalse(sid.is_configured())
            self.assertIsNone(sid.id_to_hex(1))
            self.assertEqual(sid.validate_hex("0" * sid.HEX_CHARS).error_code, "bad_pepper_file")
        finally:
            loop_path.unlink(missing_ok=True)
            sid.configure_sql_id({"pepper_file_location": str(self.test_pepper_path)})

    def test_encoding_is_deterministic_for_same_password_id_and_label(self) -> None:
        first = self.assert_public_hex(sid.id_to_hex(123))
        second = self.assert_public_hex(sid.id_to_hex("123"))
        third = self.assert_public_hex(sid.id_to_hex(123))
        self.assertEqual(first, second)
        self.assertEqual(second, third)

        labeled_first = self.assert_public_hex(sid.id_to_hex_label(123, 1))
        labeled_second = self.assert_public_hex(sid.id_to_hex_label("123", 1))
        labeled_third = self.assert_public_hex(sid.id_to_hex_label(123, 1))
        self.assertEqual(labeled_first, labeled_second)
        self.assertEqual(labeled_second, labeled_third)

    def test_same_id_across_labels_uses_label_domain_inside_tag(self) -> None:
        encoded_by_label = {label: self.assert_public_hex(sid.id_to_hex_label(42, label)) for label in range(1, 31)}
        encoded_by_label[0] = self.assert_public_hex(sid.id_to_hex(42))

        self.assertEqual(len(set(encoded_by_label.values())), len(encoded_by_label))
        for label, encoded in encoded_by_label.items():
            with self.subTest(label=label):
                if label == sid.NO_LABEL:
                    self.assertEqual(sid.hex_to_id(encoded), 42)
                else:
                    self.assertEqual(sid.hex_to_id_label(encoded, label), 42)
                    self.assertIsNone(sid.hex_to_id(encoded))
                result = sid.inspect_hex(encoded)
                self.assertTrue(result.ok)
                self.assertEqual(result.label_id, label)
                self.assertEqual(result.id, 42)

    def test_different_password_cannot_decode_existing_public_id(self) -> None:
        encoded_values = [
            self.assert_public_hex(sid.id_to_hex(123)),
            self.assert_public_hex(sid.id_to_hex_label(123, 1)),
        ]
        with patched_password(OTHER_TEST_PASSWORD):
            for encoded in encoded_values:
                with self.subTest(encoded=encoded):
                    self.assertIsNone(sid.hex_to_id(encoded))
                    self.assertIsNone(sid.hex_to_id_label(encoded, 1))
                    self.assertFalse(sid.inspect_hex(encoded).ok)

    def test_different_pepper_cannot_decode_existing_public_id(self) -> None:
        other_pepper_path = self.test_dir / "other_decode_sql_id_pepper_v1.key"
        write_test_pepper(other_pepper_path, OTHER_TEST_PEPPER_HEX)
        encoded_values = [
            self.assert_public_hex(sid.id_to_hex(123)),
            self.assert_public_hex(sid.id_to_hex_label(123, 1)),
        ]
        try:
            sid.configure_sql_id({"pepper_file_location": str(other_pepper_path)})
            for encoded in encoded_values:
                with self.subTest(encoded=encoded):
                    self.assertIsNone(sid.hex_to_id(encoded))
                    self.assertIsNone(sid.hex_to_id_label(encoded, 1))
                    self.assertFalse(sid.inspect_hex(encoded).ok)
        finally:
            other_pepper_path.chmod(0o600) if other_pepper_path.exists() else None
            other_pepper_path.unlink(missing_ok=True)
            sid.configure_sql_id({"pepper_file_location": str(self.test_pepper_path)})

    def test_pepper_file_changes_require_explicit_reload(self) -> None:
        first = self.assert_public_hex(sid.id_to_hex(123))
        write_test_pepper(self.test_pepper_path, OTHER_TEST_PEPPER_HEX)

        self.assertEqual(sid.id_to_hex(123), first)

        sid.reload_sql_id_pepper()
        second = self.assert_public_hex(sid.id_to_hex(123))
        self.assertNotEqual(second, first)
        self.assertIsNone(sid.hex_to_id(first))

    def test_invalid_id_inputs_return_none(self) -> None:
        invalid_base_values = [
            None,
            True,
            False,
            0,
            -1,
            sid.MAX_ID + 1,
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

        for value in invalid_base_values:
            with self.subTest(value=repr(value)):
                self.assertIsNone(sid.id_to_hex(value))
                self.assertIsNone(sid.id_to_hex_label(value, 1))

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
            (b"00000000000000000000000000000000", "not_string"),
            ("", "unsupported_length"),
            ("0", "unsupported_length"),
            ("0" * 16, "unsupported_length"),
            ("0" * 31, "unsupported_length"),
            ("0" * 33, "unsupported_length"),
            ("g" * sid.HEX_CHARS, "invalid_hex"),
            ("z" * sid.HEX_CHARS, "invalid_hex"),
            (" " * sid.HEX_CHARS, "invalid_hex"),
            ([], "not_string"),
            ({}, "not_string"),
            (object(), "not_string"),
        ]

        for value, code in cases:
            with self.subTest(value=repr(value)):
                self.assertIsNone(sid.hex_to_id(value))
                self.assertIsNone(sid.hex_to_id_label(value, 1))
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
            short_result = sid.validate_hex("g" * 31)
            self.assertFalse(short_result.ok)
            self.assertEqual(short_result.error_code, "unsupported_length")

            long_result = sid.validate_hex(NoLowerString("g" * 1000))
            self.assertFalse(long_result.ok)
            self.assertEqual(long_result.error_code, "unsupported_length")
            self.assertIsNone(long_result.public_hex)

    def test_all_zero_hex_is_rejected_with_validation_detail(self) -> None:
        value = "0" * sid.HEX_CHARS
        result = sid.validate_hex(value)
        self.assertFalse(result.ok)
        self.assertIsNotNone(result.layout)
        self.assertEqual(result.error_code, "tag_mismatch")
        self.assertIsNone(sid.hex_to_id(value))

    def test_single_nibble_tampering_is_rejected(self) -> None:
        cases = [
            (self.assert_public_hex(sid.id_to_hex(1)), None),
            (self.assert_public_hex(sid.id_to_hex(sid.MAX_ID)), None),
            (self.assert_public_hex(sid.id_to_hex_label(123, 1)), 1),
            (self.assert_public_hex(sid.id_to_hex_label(sid.MAX_ID, 30)), 30),
        ]

        for encoded, label in cases:
            for position, original in enumerate(encoded):
                replacement = "0" if original != "0" else "1"
                tampered = encoded[:position] + replacement + encoded[position + 1 :]
                with self.subTest(encoded=encoded, label=label, position=position):
                    self.assertIsNone(sid.hex_to_id(tampered))
                    if label is not None:
                        self.assertIsNone(sid.hex_to_id_label(tampered, label))
                    self.assertFalse(sid.inspect_hex(tampered).ok)

    def test_reserved_versions_are_rejected(self) -> None:
        round_keys, tag_key = sid._key_material()
        id_value = 1
        for reserved_version in [0, sid.RESERVED_VERSION]:
            with self.subTest(reserved_version=reserved_version):
                plain = sid._pack_plain(reserved_version, sid.NO_LABEL, id_value, tag_key)
                encoded = f"{sid._feistel_encrypt(plain, round_keys):0{sid.HEX_CHARS}x}"

                result = sid.validate_hex(encoded)
                self.assertFalse(result.ok)
                self.assertEqual(result.error_code, "tag_mismatch")
                self.assertIsNone(sid.hex_to_id(encoded))

    def test_latest_version_is_always_accepted_and_older_versions_can_be_disabled(self) -> None:
        version_1_hex = self.assert_public_hex(sid.id_to_hex(123))

        os.environ["SQL_ID_LIBRARY_PASSWORD_HEX_v2"] = OTHER_TEST_PASSWORD
        os.environ["SQL_ID_LIBRARY_DOMAIN_SALT_HEX_v2"] = OTHER_TEST_DOMAIN_SALT_HEX
        pepper_v2_path = self.test_dir / "test_sql_id_pepper_v2.key"
        write_test_pepper(pepper_v2_path, OTHER_TEST_PEPPER_HEX)
        try:
            self.assertEqual(sid.configured_issue_version(), 2)
            version_2_hex = self.assert_public_hex(sid.id_to_hex(123))
            self.assertNotEqual(version_1_hex, version_2_hex)
            self.assertEqual(sid.validate_hex(version_2_hex).version, 2)
            self.assertEqual(sid.hex_to_id(version_2_hex), 123)
            self.assertEqual(sid.hex_to_id(version_1_hex), 123)

            sid.configure_sql_id({"allowed_versions": [2]})
            self.assertEqual(sid.configured_issue_version(), 2)
            self.assertEqual(sid.hex_to_id(version_2_hex), 123)
            self.assertIsNone(sid.hex_to_id(version_1_hex))
            self.assertEqual(sid.validate_hex(version_1_hex).error_code, "unsupported_version")

            sid.configure_sql_id({"allowed_versions": [1]})
            self.assertEqual(sid.configured_issue_version(), 2)
            self.assertEqual(sid.hex_to_id(version_2_hex), 123)
            self.assertEqual(sid.hex_to_id(version_1_hex), 123)
        finally:
            os.environ.pop("SQL_ID_LIBRARY_PASSWORD_HEX_v2", None)
            os.environ.pop("SQL_ID_LIBRARY_DOMAIN_SALT_HEX_v2", None)
            pepper_v2_path.chmod(0o600) if pepper_v2_path.exists() else None
            pepper_v2_path.unlink(missing_ok=True)
            sid.configure_sql_id({"allowed_versions": sorted(sid.DEFAULT_ALLOWED_VERSIONS)})

    def test_partial_higher_version_fails_closed_instead_of_falling_back(self) -> None:
        version_1_hex = self.assert_public_hex(sid.id_to_hex(123))

        os.environ["SQL_ID_LIBRARY_PASSWORD_HEX_v2"] = OTHER_TEST_PASSWORD
        os.environ["SQL_ID_LIBRARY_DOMAIN_SALT_HEX_v2"] = OTHER_TEST_DOMAIN_SALT_HEX
        try:
            self.assertIsNone(sid.configured_issue_version())
            self.assertFalse(sid.is_configured())
            self.assertIsNone(sid.id_to_hex(123))

            result = sid.validate_hex(version_1_hex)
            self.assertFalse(result.ok)
            self.assertEqual(result.error_code, "missing_pepper_file")
        finally:
            os.environ.pop("SQL_ID_LIBRARY_PASSWORD_HEX_v2", None)
            os.environ.pop("SQL_ID_LIBRARY_DOMAIN_SALT_HEX_v2", None)

    def test_valid_tag_for_reserved_label_is_rejected(self) -> None:
        round_keys, tag_key = sid._key_material()
        plain = sid._pack_plain(sid.ISSUE_VERSION, sid.RESERVED_LABEL, 1, tag_key)
        encoded = f"{sid._feistel_encrypt(plain, round_keys):0{sid.HEX_CHARS}x}"

        result = sid.inspect_hex(encoded)
        self.assertFalse(result.ok)
        self.assertEqual(result.error_code, "reserved_label")
        self.assertIsNone(sid.hex_to_id(encoded))
        self.assertIsNone(sid.hex_to_id_label(encoded, sid.MAX_LABEL))

    def test_valid_tag_for_noncanonical_range_ids_is_rejected(self) -> None:
        round_keys, tag_key = sid._key_material()
        cases = [
            (sid.SMALL_RANGE_CLASS, 0),
            (sid.BIGINT_RANGE_CLASS, sid.SMALL_RANGE_MAX_ID),
        ]

        for range_class, id_value in cases:
            with self.subTest(range_class=range_class, id_value=id_value):
                tag = sid._tag(sid.ISSUE_VERSION, sid.NO_LABEL, range_class, id_value, tag_key)
                plain = sid._pack_plain_fields(sid.ISSUE_VERSION, sid.NO_LABEL, range_class, id_value, tag)
                encoded = f"{sid._feistel_encrypt(plain, round_keys):0{sid.HEX_CHARS}x}"

                result = sid.validate_hex(encoded)
                self.assertFalse(result.ok)
                self.assertEqual(result.error_code, "id_out_of_range")
                self.assertIsNone(sid.hex_to_id(encoded))

    def test_tag_mismatch_is_rejected(self) -> None:
        for encoded, validator in [
            (self.assert_public_hex(sid.id_to_hex(1)), sid.validate_hex),
            (self.assert_public_hex(sid.id_to_hex_label(1, 1)), lambda value: sid.validate_hex_label(value, 1)),
        ]:
            round_keys, _tag_key = sid._key_material()
            plain = sid._feistel_decrypt(int(encoded, 16), round_keys)

            # Flip one bit in the compact tag field, then re-encrypt so the outer
            # Feistel layer is well-formed but the keyed tag is wrong.
            bad_plain = plain ^ 1
            bad_encoded = f"{sid._feistel_encrypt(bad_plain, round_keys):0{sid.HEX_CHARS}x}"

            result = validator(bad_encoded)
            self.assertFalse(result.ok)
            self.assertEqual(result.error_code, "tag_mismatch")
            self.assertIsNone(sid.hex_to_id(bad_encoded))

    def test_private_pack_unpack_round_trip(self) -> None:
        _round_keys, tag_key = sid._key_material()
        for label in [0, 1, 30]:
            for id_value in [1, 123, sid.SMALL_RANGE_MAX_ID, sid.BIGINT_RANGE_MIN_ID, sid.MAX_ID]:
                with self.subTest(label=label, id_value=id_value):
                    expected_range = sid.DEFAULT_LAYOUT.range_for_id(id_value)
                    plain = sid._pack_plain(sid.ISSUE_VERSION, label, id_value, tag_key)
                    version, unpacked_label, range_class, unpacked_id, supplied_tag = sid._unpack_plain(plain)
                    self.assertEqual(version, sid.ISSUE_VERSION)
                    self.assertEqual(unpacked_label, label)
                    self.assertEqual(range_class, expected_range.range_class)
                    self.assertEqual(unpacked_id, id_value)
                    self.assertTrue(
                        sid._tags_equal(
                            supplied_tag,
                            sid._tag(sid.ISSUE_VERSION, label, range_class, id_value, tag_key),
                            expected_range,
                        )
                    )

    def test_private_helpers_reject_out_of_range_values(self) -> None:
        round_keys, tag_key = sid._key_material()
        with self.assertRaises(ValueError):
            sid._pack_plain(-1, 0, 0, tag_key)
        with self.assertRaises(ValueError):
            sid._pack_plain(8, 0, 0, tag_key)
        with self.assertRaises(ValueError):
            sid._pack_plain(sid.ISSUE_VERSION, -1, 0, tag_key)
        with self.assertRaises(ValueError):
            sid._pack_plain(sid.ISSUE_VERSION, 32, 0, tag_key)
        with self.assertRaises(ValueError):
            sid._pack_plain(sid.ISSUE_VERSION, 0, 0, tag_key)
        with self.assertRaises(ValueError):
            sid._pack_plain(sid.ISSUE_VERSION, 0, sid.MAX_ID + 1, tag_key)
        with self.assertRaises(ValueError):
            sid._pack_plain(sid.ISSUE_VERSION, 0, sid.SMALL_RANGE_MAX_ID, tag_key, range_class=sid.BIGINT_RANGE_CLASS)
        with self.assertRaises(ValueError):
            sid._pack_plain_fields(sid.ISSUE_VERSION, 0, sid.SMALL_RANGE_CLASS, 1, 1 << sid.SMALL_TAG_BITS)
        with self.assertRaises(ValueError):
            sid._tag(8, 0, sid.SMALL_RANGE_CLASS, 1, tag_key)
        with self.assertRaises(ValueError):
            sid._tag(sid.ISSUE_VERSION, 32, sid.SMALL_RANGE_CLASS, 1, tag_key)
        with self.assertRaises(ValueError):
            sid._tag(sid.ISSUE_VERSION, 0, 2, 1, tag_key)
        with self.assertRaises(ValueError):
            sid._tag(sid.ISSUE_VERSION, 0, sid.BIGINT_RANGE_CLASS, 1 << sid.BIGINT_ID_BITS, tag_key)
        with self.assertRaises(ValueError):
            sid._feistel_encrypt(-1, round_keys)
        with self.assertRaises(ValueError):
            sid._feistel_decrypt(1 << sid.TOTAL_BITS, round_keys)
        with self.assertRaises(ValueError):
            sid._unpack_plain(1 << sid.TOTAL_BITS)

    def test_feistel_permutation_inverse_on_representative_values(self) -> None:
        round_keys, tag_key = sid._key_material()
        representatives = [
            0,
            1,
            (1 << sid.DEFAULT_LAYOUT.half_bits) - 1,
            1 << sid.DEFAULT_LAYOUT.half_bits,
            sid._pack_plain(sid.ISSUE_VERSION, sid.NO_LABEL, 1, tag_key),
            sid._pack_plain(sid.ISSUE_VERSION, 1, sid.SMALL_RANGE_MAX_ID, tag_key),
            sid._pack_plain(sid.ISSUE_VERSION, 30, sid.MAX_ID, tag_key),
            (1 << sid.TOTAL_BITS) - 1,
        ]

        encrypted_values = set()
        for value in representatives:
            with self.subTest(value=value):
                encrypted = sid._feistel_encrypt(value, round_keys)
                self.assertNotIn(encrypted, encrypted_values)
                encrypted_values.add(encrypted)
                self.assertEqual(sid._feistel_decrypt(encrypted, round_keys), value)

    def test_no_collisions_for_sequential_smoke_sample(self) -> None:
        for label in [0, 1, 2, 30]:
            seen: set[str] = set()
            for id_value in range(1, 501):
                with self.subTest(label=label, id_value=id_value):
                    if label == sid.NO_LABEL:
                        encoded = sid.id_to_hex(id_value)
                        decoded = sid.hex_to_id(encoded)
                    else:
                        encoded = sid.id_to_hex_label(id_value, label)
                        decoded = sid.hex_to_id_label(encoded, label)
                    self.assertIsNotNone(encoded)
                    assert encoded is not None
                    self.assertNotIn(encoded, seen)
                    seen.add(encoded)
                    self.assertEqual(decoded, id_value)

    def test_security_math_for_exact_label_decoding_and_generic_inspection(self) -> None:
        guesses_per_year = 10 * 2 * 24 * 365
        self.assertEqual(guesses_per_year, 175_200)

        strict_expected_years = (1 << 64) / guesses_per_year
        any_label_years = ((1 << 64) / (sid.MAX_LABEL + 1)) / guesses_per_year
        self.assertAlmostEqual(strict_expected_years, 105_289_635_123_913, delta=1)
        self.assertAlmostEqual(any_label_years, 3_396_439_842_707, delta=1)

        strict_probability = sid.DEFAULT_LAYOUT.valid_id_count / (1 << sid.TOTAL_BITS)
        any_label_probability = ((sid.MAX_LABEL + 1) * sid.DEFAULT_LAYOUT.valid_id_count) / (1 << sid.TOTAL_BITS)

        self.assertEqual(sid.DEFAULT_LAYOUT.random_valid_probability_for_expected_label, strict_probability)
        self.assertEqual(sid.DEFAULT_LAYOUT.random_valid_probability_for_any_label, any_label_probability)
        self.assertLess(sid.DEFAULT_LAYOUT.valid_id_count * (1 << 64), 1 << sid.TOTAL_BITS)
        self.assertGreater(
            sid.DEFAULT_LAYOUT.valid_id_count * 100 * (1 << 64),
            99 * (1 << sid.TOTAL_BITS),
        )
        self.assertLess((sid.MAX_LABEL + 1) * sid.DEFAULT_LAYOUT.valid_id_count, 1 << 69)

        self.assertIn("105_289_635_123_913 years", sid.__doc__ or "")
        self.assertIn("175_200 guesses", sid.__doc__ or "")
        self.assertIn("inspect_hex()", sid.__doc__ or "")
