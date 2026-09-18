from __future__ import annotations

import importlib.util
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch


class ActionPathPolicyTests(unittest.TestCase):
    """Exercise the real API using only disposable server state and files."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)

        # server.py initializes state at import time relative to __file__.
        # Load a temporary copy so real tokens, audit history and data are untouched.
        source = Path(__file__).resolve().parents[1] / "server.py"
        copy = root / "server.py"
        shutil.copyfile(source, copy)
        spec = importlib.util.spec_from_file_location("nexo_test_server", copy)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

        self.secret_paths = (
            ".env", "credentials.json", "secrets.json", "id_rsa",
            "id_ed25519", "private.key", "certificate.pem", "bundle.p12",
            "bundle.pfx", "vault.kdbx", "nested/.env",
        )
        self.synthetic_secret = "SYNTHETIC TEST CONTENT ONLY"
        for name in self.secret_paths:
            target = self.module.SANDBOX_DIR / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(self.synthetic_secret, encoding="utf-8")

        logging = patch.object(self.module.NEXOHandler, "log_message")
        logging.start()
        self.addCleanup(logging.stop)
        self.server = self.module.ThreadingHTTPServer(
            ("127.0.0.1", 0), self.module.NEXOHandler,
        )
        self.addCleanup(self.server.server_close)
        self.module.PORT = self.server.server_port
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.shutdown)

    def post(self, endpoint, payload, *, human=False):
        headers = {"Content-Type": "application/json"}
        if human:
            headers["Cookie"] = (
                f"{self.module.CONTROL_COOKIE_NAME}="
                f"{self.module.CONTROL_SESSION_TOKEN}"
            )
        else:
            headers["X-NEXO-Agent-Token"] = self.module.AGENT_TOKEN
        connection = HTTPConnection("127.0.0.1", self.module.PORT, timeout=5)
        try:
            connection.request(
                "POST", endpoint, json.dumps(payload), headers,
            )
            response = connection.getresponse()
            body = json.loads(response.read())
            self.assertEqual(response.status, 200, body)
            return body
        finally:
            connection.close()

    def assert_secret_denied(self, raw, *, operation="read", human=False):
        endpoint = "/api/demo-action" if human else "/api/action"
        with patch.object(
            self.module, "execute_operation", return_value={"content": self.synthetic_secret},
        ) as execute:
            body = self.post(endpoint, {"operation": operation, "path": raw}, human=human)
        self.assertEqual(body["evaluation"]["decision"], "DENY", body)
        self.assertEqual(body["evaluation"]["policy_id"], "PG-SECRET-001", body)
        self.assertFalse(body["executed"])
        self.assertFalse(body["pending_approval"])
        self.assertNotIn(self.synthetic_secret, json.dumps(body))
        execute.assert_not_called()
        self.assertEqual(self.module.PENDING, {})

    def test_secret_aliases_are_denied_before_execution(self):
        for name in self.secret_paths:
            for suffix in ("", "/.", "/./", "\\.", "/././"):
                with self.subTest(path=name + suffix):
                    self.assert_secret_denied(name + suffix)

        valid, count, message = self.module.audit.verify()
        self.assertTrue(valid, message)
        self.assertEqual(count, len(self.secret_paths) * 5)
        for entry in self.module.audit.load():
            self.assertIn(entry["path"], self.secret_paths)
            self.assertEqual(entry["decision"], "DENY")

    @unittest.skipUnless(os.name == "nt", "Windows filename normalization")
    def test_windows_secret_aliases_are_denied(self):
        for name in self.secret_paths:
            for suffix in (".", "..", " ./."):
                with self.subTest(path=name + suffix):
                    self.assert_secret_denied(name + suffix)

    def test_human_demo_uses_the_same_secret_policy(self):
        self.assert_secret_denied(".env/.", human=True)

    def test_secret_mutations_are_denied_without_pending_approval(self):
        for operation in ("write", "delete", "mkdir"):
            with self.subTest(operation=operation):
                self.assert_secret_denied(".env/.", operation=operation)
        self.assertEqual(
            (self.module.SANDBOX_DIR / ".env").read_text(encoding="utf-8"),
            self.synthetic_secret,
        )

    def test_safe_read_alias_uses_the_canonical_path(self):
        body = self.post("/api/action", {"operation": "read", "path": "welcome.txt/."})
        self.assertEqual(body["evaluation"]["decision"], "ALLOW")
        self.assertEqual(body["evaluation"]["path"], "welcome.txt")
        self.assertTrue(body["executed"])
        self.assertEqual(body["result"]["path"], "welcome.txt")
        self.assertIn("NEXO Privilege Gate", body["result"]["content"])

    def test_traversal_still_denied_before_normalization(self):
        with patch.object(self.module, "execute_operation") as execute:
            body = self.post("/api/action", {"operation": "read", "path": "nested/../welcome.txt"})
        self.assertEqual(body["evaluation"]["policy_id"], "PG-PATH-001")
        self.assertFalse(body["executed"])
        execute.assert_not_called()

    def test_canonical_write_still_requires_human_approval(self):
        body = self.post("/api/action", {
            "operation": "write", "path": "./notes.txt", "content": "approved content",
        })
        self.assertEqual(body["evaluation"]["decision"], "REVIEW")
        self.assertEqual(body["evaluation"]["path"], "notes.txt")
        self.assertFalse(body["executed"])
        self.assertTrue(body["pending_approval"])
        pending = self.module.PENDING[body["request_id"]]
        self.assertEqual(pending["payload"]["path"], "notes.txt")
        target = self.module.SANDBOX_DIR / "notes.txt"
        self.assertNotEqual(target.read_text(encoding="utf-8"), "approved content")
        approved = self.post("/api/approve", {"request_id": body["request_id"]}, human=True)
        self.assertTrue(approved["executed"])
        self.assertEqual(target.read_text(encoding="utf-8"), "approved content")

    def test_root_listing_still_allowed(self):
        body = self.post("/api/action", {"operation": "list", "path": ""})
        self.assertEqual(body["evaluation"]["decision"], "ALLOW")
        self.assertEqual(body["evaluation"]["path"], ".")
        self.assertTrue(body["executed"])
        names = {entry["name"] for entry in body["result"]["entries"]}
        self.assertIn("welcome.txt", names)
        self.assertNotIn(".nexo_trash", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
