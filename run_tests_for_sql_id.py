#!/usr/bin/env python3
"""Tests for sql_id_library.py.

Run with:
    XCTX_ID_PASSWORD="$(python -c 'import secrets; print(secrets.token_hex(32))')" python run_tests_for_sql_id.py

The tests set a safe default test password and per-test pepper file, then also
cover missing, weak, low-diversity, wrong-password, and wrong-pepper behavior.
"""

from __future__ import annotations

import os
import re
import unittest
import builtins
from contextlib import contextmanager
from pathlib import Path
from unittest import mock


TEST_PASSWORD = "unit-test-secret-" + ("0123456789abcdef" * 4)
OTHER_TEST_PASSWORD = "different-test-secret-" + ("fedcba9876543210" * 4)
TEST_PEPPER_HEX = "0123456789abcdef" * 4
OTHER_TEST_PEPPER_HEX = "fedcba9876543210" * 4
TEST_DIR = Path(__file__).resolve().parent
TEST_CONF_DIR = TEST_DIR / "conf"
TEST_PEPPER_PATH = TEST_DIR / "test_sql_id_pepper.key"
os.environ.setdefault("XCTX_ID_PASSWORD", TEST_PASSWORD)
os.environ["XCTX_DEMO_ALLOW_BUNDLED_DOMAIN_SALT"] = "1"

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


def write_test_pepper(path: Path, value: str = TEST_PEPPER_HEX, mode: int = 0o400) -> None:
    """Write a test pepper file with intentionally narrow permissions."""
    path.unlink(missing_ok=True)
    path.write_text(value + "\n", encoding="ascii")
    path.chmod(mode)


@contextmanager
def patched_password(value: str | None):
    """Temporarily patch XCTX_ID_PASSWORD for tests."""
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


class SqlIdLibraryTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ[sid.ENV_PASSWORD_NAME] = TEST_PASSWORD
        write_test_pepper(TEST_PEPPER_PATH)
        sid.clear_sql_id_config()
        sid.configure_sql_id({"pepper_file_location": str(TEST_PEPPER_PATH)})

    def tearDown(self) -> None:
        TEST_PEPPER_PATH.chmod(0o600) if TEST_PEPPER_PATH.exists() else None
        TEST_PEPPER_PATH.unlink(missing_ok=True)

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
        self.assertEqual(sid.DEMO_ALLOW_BUNDLED_DOMAIN_SALT_ENV, "XCTX_DEMO_ALLOW_BUNDLED_DOMAIN_SALT")
        self.assertEqual(sid.ISSUE_VERSION, 2)
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
        self.assertGreaterEqual(sid.MIN_PASSWORD_BYTES, 32)
        self.assertEqual(sid.DEFAULT_PEPPER_FILE_LOCATION, "~/.sql_hex_id_pepper_file.key")
        self.assertEqual(sid.MIN_PEPPER_HEX_CHARS, 64)
        self.assertEqual(sid.MAX_PEPPER_HEX_CHARS, 256)
        self.assertEqual(sid.MIN_PEPPER_BYTES, 32)
        self.assertEqual(sid.MAX_PEPPER_BYTES, 128)
        self.assertEqual(sid.configured_pepper_file_location(), str(TEST_PEPPER_PATH))
        self.assertGreaterEqual(sid.ROUNDS, 12)
        self.assertRegex(sid.DOMAIN_SALT_HEX, re.compile(r"^[0-9a-fA-F]{64}$"))
        self.assertEqual(len(bytes.fromhex(sid.DOMAIN_SALT_HEX)), 32)
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

    def test_configure_sql_id_accepts_pepper_path_labels_or_both(self) -> None:
        other_pepper_path = TEST_DIR / "other_test_sql_id_pepper.key"
        write_test_pepper(other_pepper_path, OTHER_TEST_PEPPER_HEX)
        try:
            sid.configure_sql_id({"labels": {"users": 1}})
            self.assertEqual(sid.available_labels(), {"users": 1})
            self.assertEqual(sid.configured_pepper_file_location(), str(TEST_PEPPER_PATH))

            sid.configure_sql_id({"pepper_file_location": str(other_pepper_path)})
            self.assertEqual(sid.available_labels(), {"users": 1})
            self.assertEqual(sid.configured_pepper_file_location(), str(other_pepper_path))

            sid.configure_sql_id({"pepper_file_location": str(TEST_PEPPER_PATH), "labels": {"plans": 2}})
            self.assertEqual(sid.available_labels(), {"plans": 2})
            self.assertEqual(sid.configured_pepper_file_location(), str(TEST_PEPPER_PATH))
        finally:
            other_pepper_path.chmod(0o600) if other_pepper_path.exists() else None
            other_pepper_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_json_file(self) -> None:
        sid.load_sql_id_config_from_file(TEST_CONF_DIR / "test_sql_id_config.json")
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
        json_path = TEST_DIR / "cached_sql_id_config.json"
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
            sid.configure_sql_id({"pepper_file_location": str(TEST_PEPPER_PATH)})
            json_path.write_text('{"labels": {"plan": 2}}\n', encoding="utf-8")
            sid.load_sql_id_config_from_file(json_path)
            self.assertEqual(sid.available_labels(), {"plan": 2})
        finally:
            json_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_file_can_set_pepper_location(self) -> None:
        json_path = TEST_DIR / "pepper_path_sql_id_config.json"
        other_pepper_path = TEST_DIR / "config_sql_id_pepper.key"
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
        json_path = TEST_DIR / "same_stem_cached_labels.json"
        yaml_path = TEST_DIR / "same_stem_cached_labels.yaml"
        json_path.write_text('{"labels": {"dry_run": 1}}\n', encoding="utf-8")
        yaml_path.write_text("labels:\n  1: dry_run\n", encoding="utf-8")
        try:
            sid.load_sql_id_config_from_file(json_path)
            self.assertEqual(sid.available_labels(), {"dry_run": 1})
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(TEST_DIR / "same_stem_cached_labels.txt")

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
        bad_json_path = TEST_DIR / "bad_sql_id_labels.json"
        bad_json_path.write_text("[1, 2, 3]", encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(bad_json_path)
            self.assertEqual(sid.available_labels(), {"users": 1})
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(TEST_DIR / "missing.sqlid")
            self.assertEqual(sid.available_labels(), {"users": 1})
        finally:
            bad_json_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_json_rejects_duplicate_keys_and_names(self) -> None:
        duplicate_key_path = TEST_DIR / "duplicate_key_sql_id_labels.json"
        duplicate_name_path = TEST_DIR / "duplicate_name_sql_id_labels.json"
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

        duplicate_key_path = TEST_DIR / "duplicate_key_sql_id_labels.yaml"
        duplicate_name_path = TEST_DIR / "duplicate_name_sql_id_labels.yaml"
        bool_key_path = TEST_DIR / "bool_key_sql_id_labels.yaml"
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
        yaml_path = TEST_DIR / "no_yaml_dependency_sql_id_labels.yaml"
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
        json_path = TEST_DIR / "mismatch_sql_id_labels.json"
        yaml_path = TEST_DIR / "mismatch_sql_id_labels.yaml"
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
        large_path = TEST_DIR / "large_sql_id_labels.json"
        large_path.write_text(" " * 2001, encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                sid.load_sql_id_config_from_file(large_path)
        finally:
            large_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_file_accepts_exactly_2000_bytes(self) -> None:
        exact_path = TEST_DIR / "exact_size_sql_id_labels.json"
        payload = '{"labels": {"dry_run": 1}}'
        exact_path.write_text(payload + (" " * (2000 - len(payload))), encoding="utf-8")
        try:
            sid.load_sql_id_config_from_file(exact_path)
            self.assertEqual(sid.available_labels(), {"dry_run": 1})
        finally:
            exact_path.unlink(missing_ok=True)

    def test_load_sql_id_config_from_file_expands_home(self) -> None:
        with mock.patch.dict(os.environ, {"HOME": str(TEST_DIR)}):
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

        with patched_password("short"):
            self.assertFalse(sid.is_configured())
            self.assertIsNone(sid.id_to_hex(1))
            self.assertEqual(sid.validate_hex("0" * sid.HEX_CHARS).error_code, "bad_config")

        with patched_password("a" * sid.MIN_PASSWORD_BYTES):
            self.assertFalse(sid.is_configured())
            self.assertIsNone(sid.id_to_hex(1))
            self.assertEqual(sid.validate_hex("0" * sid.HEX_CHARS).error_code, "bad_config")

        with patched_password("0123456789abcdef" * 2):
            self.assertTrue(sid.is_configured())
            self.assertIsNotNone(sid.id_to_hex(1))

    def test_bundled_domain_salt_requires_demo_override(self) -> None:
        self.assertEqual(sid.DOMAIN_SALT_HEX, sid.BUNDLED_DOMAIN_SALT_HEX)
        self.assertTrue(sid.is_configured())

        with patched_env_var(sid.DEMO_ALLOW_BUNDLED_DOMAIN_SALT_ENV, None):
            self.assertFalse(sid.is_configured())
            self.assertIsNone(sid.id_to_hex(1))
            result = sid.validate_hex("0" * sid.HEX_CHARS)
            self.assertFalse(result.ok)
            self.assertEqual(result.error_code, "bad_config")
            self.assertIn(sid.DEMO_ALLOW_BUNDLED_DOMAIN_SALT_ENV, result.error or "")

            missing_pepper_path = TEST_DIR / "missing_for_salt_order.key"
            missing_pepper_path.unlink(missing_ok=True)
            sid.configure_sql_id({"pepper_file_location": str(missing_pepper_path)})
            result = sid.validate_hex("0" * sid.HEX_CHARS)
            self.assertFalse(result.ok)
            self.assertEqual(result.error_code, "bad_config")
            self.assertIn(sid.DEMO_ALLOW_BUNDLED_DOMAIN_SALT_ENV, result.error or "")
            sid.configure_sql_id({"pepper_file_location": str(TEST_PEPPER_PATH)})

        with patched_env_var(sid.DEMO_ALLOW_BUNDLED_DOMAIN_SALT_ENV, "1"):
            self.assertTrue(sid.is_configured())
            self.assertIsNotNone(sid.id_to_hex(1))

    def test_private_domain_salt_does_not_require_demo_override(self) -> None:
        private_salt_hex = "1234567890abcdef" * 4
        old_domain_salt_hex = sid.DOMAIN_SALT_HEX
        old_domain_salt = sid._DOMAIN_SALT
        try:
            sid.DOMAIN_SALT_HEX = private_salt_hex
            sid._DOMAIN_SALT = bytes.fromhex(private_salt_hex)
            sid._derive_material.cache_clear()

            with patched_env_var(sid.DEMO_ALLOW_BUNDLED_DOMAIN_SALT_ENV, None):
                self.assertTrue(sid.is_configured())
                self.assertIsNotNone(sid.id_to_hex(1))
        finally:
            sid.DOMAIN_SALT_HEX = old_domain_salt_hex
            sid._DOMAIN_SALT = old_domain_salt
            sid._derive_material.cache_clear()

    def test_pepper_file_config_errors_are_specific(self) -> None:
        cases = [
            ("missing_sql_id_pepper.key", None, None, "missing_pepper_file"),
            ("short_sql_id_pepper.key", "0123456789abcdef", 0o400, "pepper_too_short"),
            ("long_sql_id_pepper.key", "01" * 129, 0o400, "pepper_too_long"),
            ("odd_sql_id_pepper.key", ("01" * 32) + "0", 0o400, "invalid_pepper_hex"),
            ("nonhex_sql_id_pepper.key", "g" * 64, 0o400, "invalid_pepper_hex"),
            ("low_diversity_sql_id_pepper.key", "00" * 32, 0o400, "low_diversity_pepper"),
            ("world_readable_sql_id_pepper.key", TEST_PEPPER_HEX, 0o644, "bad_pepper_permissions"),
        ]

        for filename, contents, mode, code in cases:
            pepper_path = TEST_DIR / filename
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
                sid.configure_sql_id({"pepper_file_location": str(TEST_PEPPER_PATH)})

    def test_pepper_file_symlink_is_rejected(self) -> None:
        if os.name != "posix" or not hasattr(os, "symlink"):
            self.skipTest("POSIX symlink behavior only")

        target_path = TEST_DIR / "target_sql_id_pepper.key"
        symlink_path = TEST_DIR / "symlink_sql_id_pepper.key"
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
            sid.configure_sql_id({"pepper_file_location": str(TEST_PEPPER_PATH)})

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
        other_pepper_path = TEST_DIR / "other_decode_sql_id_pepper.key"
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
            sid.configure_sql_id({"pepper_file_location": str(TEST_PEPPER_PATH)})

    def test_pepper_file_changes_require_explicit_reload(self) -> None:
        first = self.assert_public_hex(sid.id_to_hex(123))
        write_test_pepper(TEST_PEPPER_PATH, OTHER_TEST_PEPPER_HEX)

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

    def test_valid_tag_for_inactive_versions_is_rejected(self) -> None:
        round_keys, tag_key = sid._key_material()
        id_value = 1
        for inactive_version in [0, 1, 6, sid.RESERVED_VERSION]:
            with self.subTest(inactive_version=inactive_version):
                plain = sid._pack_plain(inactive_version, sid.NO_LABEL, id_value, tag_key)
                encoded = f"{sid._feistel_encrypt(plain, round_keys):0{sid.HEX_CHARS}x}"

                result = sid.validate_hex(encoded)
                self.assertFalse(result.ok)
                self.assertEqual(result.error_code, "unsupported_version")
                self.assertIsNone(sid.hex_to_id(encoded))

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
