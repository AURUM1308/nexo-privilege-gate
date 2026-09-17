from __future__ import annotations

from pathlib import Path
from typing import Any

import hashlib
import hmac
import json
import os
import secrets


class AuditLog:
    """
    Tamper-evident local audit log for NEXO Privilege Gate.

    Each record contains the MAC of the previous record and
    receives its own HMAC-SHA256 authentication code.

    This detects modification of the log as long as the local
    audit key remains secret.

    It is not intended to protect against an attacker who has
    full control of both the log and the key.
    """

    def __init__(
        self,
        state_dir: Path,
    ) -> None:

        self.state_dir = state_dir.resolve()

        self.state_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.key_path = (
            self.state_dir
            / "audit.key"
        )

        self.log_path = (
            self.state_dir
            / "audit.jsonl"
        )

        self.key = (
            self._load_or_create_key()
        )


    # ---------------------------------------------------------
    # KEY MANAGEMENT
    # ---------------------------------------------------------

    def _load_or_create_key(
        self,
    ) -> bytes:
        """
        Load the local audit key or generate one on first launch.
        """

        if self.key_path.exists():

            key = self.key_path.read_bytes()

            if len(key) < 32:

                raise ValueError(
                    "Existing audit key is unexpectedly short."
                )

            return key


        key = secrets.token_bytes(
            32
        )

        self.key_path.write_bytes(
            key
        )


        # Restrictive permissions on platforms that honor chmod.
        try:

            os.chmod(
                self.key_path,
                0o600,
            )

        except OSError:
            pass


        return key


    # ---------------------------------------------------------
    # CANONICAL SERIALIZATION
    # ---------------------------------------------------------

    @staticmethod
    def _canonical(
        record_without_mac: dict[str, Any],
    ) -> bytes:
        """
        Serialize records deterministically so verification
        produces exactly the same HMAC.
        """

        return json.dumps(
            record_without_mac,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode(
            "utf-8"
        )


    # ---------------------------------------------------------
    # STORAGE
    # ---------------------------------------------------------

    def load(
        self,
    ) -> list[dict[str, Any]]:
        """
        Read all audit records from disk.
        """

        if not self.log_path.exists():

            return []


        entries: list[
            dict[str, Any]
        ] = []


        for line_number, line in enumerate(
            self.log_path.read_text(
                encoding="utf-8"
            ).splitlines(),
            start=1,
        ):

            if not line.strip():
                continue


            try:

                record = json.loads(
                    line
                )

            except json.JSONDecodeError as exc:

                raise ValueError(
                    (
                        "Invalid JSON in audit log "
                        f"at line {line_number}."
                    )
                ) from exc


            if not isinstance(
                record,
                dict,
            ):

                raise ValueError(
                    (
                        "Audit record "
                        f"{line_number} is not an object."
                    )
                )


            entries.append(
                record
            )


        return entries


    def append(
        self,
        event: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Append a new authenticated record.
        """

        entries = self.load()


        previous_mac = (
            entries[-1]["mac"]
            if entries
            else "GENESIS"
        )


        record = {
            **event,

            "prev_mac":
                previous_mac,
        }


        mac = hmac.new(
            self.key,
            self._canonical(
                record
            ),
            hashlib.sha256,
        ).hexdigest()


        record["mac"] = mac


        serialized = json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
        )


        with self.log_path.open(
            "a",
            encoding="utf-8",
            newline="\n",
        ) as handle:

            handle.write(
                serialized
                + "\n"
            )

            handle.flush()

            try:
                os.fsync(
                    handle.fileno()
                )
            except OSError:
                pass


        return record


    # ---------------------------------------------------------
    # VERIFICATION
    # ---------------------------------------------------------

    def verify(
        self,
    ) -> tuple[
        bool,
        int,
        str,
    ]:
        """
        Verify the full HMAC chain.

        Returns:
            success
            number of successfully verified records
            status message
        """

        try:

            entries = self.load()

        except Exception as exc:

            return (
                False,
                0,
                (
                    "Could not parse audit log: "
                    f"{exc}"
                ),
            )


        previous_mac = "GENESIS"


        for index, entry in enumerate(
            entries,
            start=1,
        ):

            supplied_prev_mac = (
                entry.get(
                    "prev_mac"
                )
            )


            if (
                supplied_prev_mac
                != previous_mac
            ):

                return (
                    False,
                    index - 1,
                    (
                        "Audit chain break detected "
                        f"at record {index}."
                    ),
                )


            supplied_mac = str(
                entry.get(
                    "mac",
                    "",
                )
            )


            if not supplied_mac:

                return (
                    False,
                    index - 1,
                    (
                        "Missing authentication code "
                        f"at record {index}."
                    ),
                )


            body = dict(
                entry
            )

            body.pop(
                "mac",
                None,
            )


            expected_mac = hmac.new(
                self.key,
                self._canonical(
                    body
                ),
                hashlib.sha256,
            ).hexdigest()


            if not hmac.compare_digest(
                supplied_mac,
                expected_mac,
            ):

                return (
                    False,
                    index - 1,
                    (
                        "Audit integrity verification "
                        f"failed at record {index}."
                    ),
                )


            previous_mac = supplied_mac


        return (
            True,
            len(entries),
            (
                "Audit chain verified successfully."
            ),
        )


    # ---------------------------------------------------------
    # MAINTENANCE
    # ---------------------------------------------------------

    def clear(
        self,
    ) -> None:
        """
        Remove the current audit log.

        The cryptographic key is deliberately preserved.
        """

        self.log_path.unlink(
            missing_ok=True
        )


    def count(
        self,
    ) -> int:

        return len(
            self.load()
        )


    def latest(
        self,
        limit: int = 100,
    ) -> list[dict[str, Any]]:

        if limit <= 0:

            return []


        entries = self.load()

        return entries[
            -limit:
        ]
