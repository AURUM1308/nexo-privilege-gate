from __future__ import annotations

import json
import tempfile
import unittest

from pathlib import Path

from nexo.audit import AuditLog
from nexo.policy import evaluate
from nexo.sandbox import (
    SandboxFS,
    SandboxViolation,
)


class PolicyTests(unittest.TestCase):

    def test_safe_read_is_allowed(self):

        result = evaluate(
            "read",
            "welcome.txt",
        )

        self.assertEqual(
            result.decision,
            "ALLOW",
        )

        self.assertLess(
            result.risk,
            35,
        )


    def test_delete_requires_review(self):

        result = evaluate(
            "delete",
            "important.txt",
        )

        self.assertEqual(
            result.decision,
            "REVIEW",
        )

        self.assertGreaterEqual(
            result.risk,
            70,
        )


    def test_write_requires_review(self):

        result = evaluate(
            "write",
            "notes.txt",
            size_bytes=100,
        )

        self.assertEqual(
            result.decision,
            "REVIEW",
        )


    def test_sensitive_env_file_is_denied(self):

        result = evaluate(
            "read",
            ".env",
        )

        self.assertEqual(
            result.decision,
            "DENY",
        )

        self.assertEqual(
            result.policy_id,
            "PG-SECRET-001",
        )


    def test_private_key_is_denied(self):

        result = evaluate(
            "read",
            "private.key",
        )

        self.assertEqual(
            result.decision,
            "DENY",
        )


    def test_invalid_operation_is_denied(self):

        result = evaluate(
            "execute",
            "anything.txt",
        )

        self.assertEqual(
            result.decision,
            "DENY",
        )


    def test_invalid_path_is_denied(self):

        result = evaluate(
            "read",
            "../outside.txt",
            path_ok=False,
            path_reason="Path traversal blocked.",
        )

        self.assertEqual(
            result.decision,
            "DENY",
        )

        self.assertEqual(
            result.policy_id,
            "PG-PATH-001",
        )


class SandboxTests(unittest.TestCase):

    def setUp(self):

        self.temp_dir = (
            tempfile.TemporaryDirectory()
        )

        self.root = Path(
            self.temp_dir.name
        )

        self.fs = SandboxFS(
            self.root
        )

        self.fs.seed()


    def tearDown(self):

        self.temp_dir.cleanup()


    def test_seed_creates_demo_files(self):

        self.assertTrue(
            (
                self.root
                / "welcome.txt"
            ).exists()
        )

        self.assertTrue(
            (
                self.root
                / "important.txt"
            ).exists()
        )


    def test_read_welcome_file(self):

        result = self.fs.read_text(
            "welcome.txt"
        )

        self.assertEqual(
            result["path"],
            "welcome.txt",
        )

        self.assertIn(
            "NEXO Privilege Gate",
            result["content"],
        )


    def test_list_directory(self):

        result = self.fs.list_dir(
            ""
        )

        names = {
            item["name"]
            for item in result
        }

        self.assertIn(
            "welcome.txt",
            names,
        )

        self.assertIn(
            "important.txt",
            names,
        )

        self.assertNotIn(
            ".nexo_trash",
            names,
        )


    def test_parent_traversal_is_blocked(self):

        with self.assertRaises(
            SandboxViolation
        ):

            self.fs.resolve(
                "../outside.txt"
            )


    def test_nested_parent_traversal_is_blocked(self):

        with self.assertRaises(
            SandboxViolation
        ):

            self.fs.resolve(
                "folder/../../outside.txt"
            )


    def test_posix_absolute_path_is_blocked(self):

        with self.assertRaises(
            SandboxViolation
        ):

            self.fs.resolve(
                "/etc/passwd"
            )


    def test_windows_drive_path_is_blocked(self):

        with self.assertRaises(
            SandboxViolation
        ):

            self.fs.resolve(
                r"C:\Users\Santiago\secret.txt"
            )


    def test_windows_alternate_data_stream_is_blocked(self):

        with self.assertRaises(
            SandboxViolation
        ):

            self.fs.resolve(
                "normal.txt:secret"
            )


    def test_unc_path_is_blocked(self):

        with self.assertRaises(
            SandboxViolation
        ):

            self.fs.resolve(
                r"\\server\share\secret.txt"
            )


    def test_direct_quarantine_access_is_blocked(self):

        with self.assertRaises(
            SandboxViolation
        ):

            self.fs.resolve(
                ".nexo_trash/file.txt"
            )


    def test_write_text(self):

        result = self.fs.write_text(
            "test.txt",
            "hello from NEXO",
        )

        self.assertEqual(
            result["path"],
            "test.txt",
        )

        self.assertEqual(
            (
                self.root
                / "test.txt"
            ).read_text(
                encoding="utf-8"
            ),
            "hello from NEXO",
        )


    def test_create_directory(self):

        result = self.fs.mkdir(
            "research"
        )

        self.assertTrue(
            result["created"]
        )

        self.assertTrue(
            (
                self.root
                / "research"
            ).is_dir()
        )


    def test_quarantine_does_not_permanently_delete(self):

        original = (
            self.root
            / "important.txt"
        )

        self.assertTrue(
            original.exists()
        )

        result = self.fs.quarantine(
            "important.txt"
        )

        self.assertTrue(
            result["quarantined"]
        )

        self.assertFalse(
            original.exists()
        )

        quarantined = (
            self.fs.trash
            / result["quarantine_id"]
        )

        self.assertTrue(
            quarantined.exists()
        )


    def test_sandbox_root_cannot_be_quarantined(self):

        with self.assertRaises(
            SandboxViolation
        ):

            self.fs.quarantine(
                ""
            )


class AuditTests(unittest.TestCase):

    def setUp(self):

        self.temp_dir = (
            tempfile.TemporaryDirectory()
        )

        self.state_dir = Path(
            self.temp_dir.name
        )

        self.audit = AuditLog(
            self.state_dir
        )


    def tearDown(self):

        self.temp_dir.cleanup()


    def test_new_audit_is_valid(self):

        valid, count, _ = (
            self.audit.verify()
        )

        self.assertTrue(
            valid
        )

        self.assertEqual(
            count,
            0,
        )


    def test_append_and_verify(self):

        self.audit.append(
            {
                "timestamp":
                    "2026-09-17T00:00:00Z",

                "event":
                    "test_event",

                "decision":
                    "ALLOW",
            }
        )

        valid, count, _ = (
            self.audit.verify()
        )

        self.assertTrue(
            valid
        )

        self.assertEqual(
            count,
            1,
        )


    def test_multiple_records_form_valid_chain(self):

        for index in range(
            3
        ):

            self.audit.append(
                {
                    "timestamp":
                        f"2026-09-17T00:00:0{index}Z",

                    "event":
                        "test_event",

                    "index":
                        index,
                }
            )

        valid, count, _ = (
            self.audit.verify()
        )

        self.assertTrue(
            valid
        )

        self.assertEqual(
            count,
            3,
        )


    def test_tampered_record_is_detected(self):

        self.audit.append(
            {
                "timestamp":
                    "2026-09-17T00:00:00Z",

                "event":
                    "policy_decision",

                "decision":
                    "DENY",
            }
        )

        lines = (
            self.audit.log_path
            .read_text(
                encoding="utf-8"
            )
            .splitlines()
        )

        record = json.loads(
            lines[0]
        )

        record["decision"] = (
            "ALLOW"
        )

        self.audit.log_path.write_text(
            json.dumps(
                record
            )
            + "\n",
            encoding="utf-8",
        )

        valid, _, message = (
            self.audit.verify()
        )

        self.assertFalse(
            valid
        )

        self.assertIn(
            "failed",
            message.lower(),
        )


    def test_chain_break_is_detected(self):

        self.audit.append(
            {
                "event":
                    "one",
            }
        )

        self.audit.append(
            {
                "event":
                    "two",
            }
        )

        lines = (
            self.audit.log_path
            .read_text(
                encoding="utf-8"
            )
            .splitlines()
        )

        second = json.loads(
            lines[1]
        )

        second["prev_mac"] = (
            "FAKE"
        )

        lines[1] = json.dumps(
            second
        )

        self.audit.log_path.write_text(
            "\n".join(
                lines
            )
            + "\n",
            encoding="utf-8",
        )

        valid, _, message = (
            self.audit.verify()
        )

        self.assertFalse(
            valid
        )

        self.assertIn(
            "chain break",
            message.lower(),
        )


if __name__ == "__main__":

    unittest.main(
        verbosity=2
    )
