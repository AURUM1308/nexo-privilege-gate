from __future__ import annotations

from dataclasses import dataclass, asdict

MAX_WRITE_BYTES = 256_000


@dataclass(frozen=True)
class Evaluation:
    decision: str
    risk: int
    policy_id: str
    reason: str
    operation: str
    path: str

    def to_dict(self) -> dict:
        return asdict(self)


SENSITIVE_NAMES = {
    ".env",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    "secrets.json",
}

SENSITIVE_SUFFIXES = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".kdbx",
}


def evaluate(
    operation: str,
    path: str,
    *,
    path_ok: bool = True,
    path_reason: str = "",
    size_bytes: int = 0,
) -> Evaluation:

    op = (operation or "").strip().lower()
    path = (path or "").strip()

    if not path_ok:
        return Evaluation(
            "DENY",
            100,
            "PG-PATH-001",
            path_reason
            or "The requested path is outside the authorized sandbox.",
            op,
            path,
        )

    if op not in {
        "list",
        "read",
        "write",
        "delete",
        "mkdir",
    }:
        return Evaluation(
            "DENY",
            100,
            "PG-OP-001",
            "Unsupported operation.",
            op,
            path,
        )

    name = (
        path
        .replace("\\", "/")
        .rstrip("/")
        .split("/")[-1]
        .lower()
        if path
        else ""
    )

    suffix = ""

    if "." in name:
        suffix = "." + name.rsplit(".", 1)[-1]

    if (
        name in SENSITIVE_NAMES
        or suffix in SENSITIVE_SUFFIXES
    ):
        return Evaluation(
            "DENY",
            95,
            "PG-SECRET-001",
            (
                "Access to common credential or "
                "secret-file formats is blocked "
                "in this beta."
            ),
            op,
            path,
        )

    if op == "list":
        return Evaluation(
            "ALLOW",
            5,
            "PG-FS-001",
            (
                "Directory listing is read-only "
                "and remains inside the sandbox."
            ),
            op,
            path,
        )

    if op == "read":
        return Evaluation(
            "ALLOW",
            10,
            "PG-FS-002",
            (
                "Text-file reading is allowed "
                "inside the sandbox."
            ),
            op,
            path,
        )

    if op == "write":

        if size_bytes > MAX_WRITE_BYTES:
            return Evaluation(
                "DENY",
                90,
                "PG-SIZE-001",
                (
                    f"Write exceeds the "
                    f"{MAX_WRITE_BYTES}-byte beta limit."
                ),
                op,
                path,
            )

        return Evaluation(
            "REVIEW",
            55,
            "PG-FS-003",
            (
                "Writing changes filesystem state "
                "and requires explicit human approval."
            ),
            op,
            path,
        )

    if op == "mkdir":
        return Evaluation(
            "REVIEW",
            45,
            "PG-FS-004",
            (
                "Creating a directory changes "
                "filesystem state and requires approval."
            ),
            op,
            path,
        )

    return Evaluation(
        "REVIEW",
        85,
        "PG-FS-005",
        (
            "Deletion is destructive. "
            "The beta requires approval and moves "
            "targets to quarantine instead of "
            "permanently deleting them."
        ),
        op,
        path,
    )
