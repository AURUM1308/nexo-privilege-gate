from __future__ import annotations

from pathlib import Path, PurePosixPath

import os
import shutil
import tempfile
import uuid


MAX_READ_BYTES = 1_000_000
MAX_WRITE_BYTES = 256_000


class SandboxViolation(ValueError):
    """
    Raised when a requested filesystem operation attempts
    to violate the sandbox security boundary.
    """
    pass


class SandboxFS:
    """
    Restricted filesystem interface used by NEXO Privilege Gate.

    The sandbox exposes only a dedicated directory.
    Requests using absolute paths, '..', drive-qualified paths,
    symbolic links or junctions are rejected.

    Destructive deletion is implemented as quarantine rather
    than permanent deletion.
    """

    def __init__(self, root: Path):

        self.root = root.resolve()

        self.root.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.trash = (
            self.root
            / ".nexo_trash"
        )

        self.trash.mkdir(
            exist_ok=True,
        )


    # ---------------------------------------------------------
    # DEMO DATA
    # ---------------------------------------------------------

    def seed(self) -> None:
        """
        Create disposable files used to demonstrate the sandbox.
        Existing files are never overwritten.
        """

        welcome = (
            self.root
            / "welcome.txt"
        )

        important = (
            self.root
            / "important.txt"
        )

        notes = (
            self.root
            / "notes.txt"
        )


        if not welcome.exists():

            welcome.write_text(
                (
                    "Welcome to NEXO Privilege Gate v0.4.\n\n"
                    "This directory is an isolated filesystem "
                    "sandbox used for security testing.\n"
                ),
                encoding="utf-8",
            )


        if not important.exists():

            important.write_text(
                (
                    "Disposable protected test file.\n"
                    "Try requesting its deletion through "
                    "NEXO Privilege Gate.\n"
                ),
                encoding="utf-8",
            )


        if not notes.exists():

            notes.write_text(
                (
                    "NEXO sandbox notes.\n"
                    "Writing changes to this file should require "
                    "human authorization.\n"
                ),
                encoding="utf-8",
            )


    # ---------------------------------------------------------
    # PATH SECURITY
    # ---------------------------------------------------------

    def _parts(
        self,
        raw: str,
    ) -> tuple[str, ...]:

        raw = (
            raw or ""
        ).strip()


        if "\x00" in raw:

            raise SandboxViolation(
                "NUL bytes are not allowed in paths."
            )


        normalized = raw.replace(
            "\\",
            "/",
        )


        # Explicitly block UNC/network style paths.
        if normalized.startswith("//"):

            raise SandboxViolation(
                "UNC or network paths are not allowed."
            )


        path = PurePosixPath(
            normalized
        )


        if path.is_absolute():

            raise SandboxViolation(
                "Absolute paths are not allowed."
            )


        parts = tuple(
            part
            for part in path.parts
            if part not in (
                "",
                ".",
            )
        )


        if any(
            part == ".."
            for part in parts
        ):

            raise SandboxViolation(
                "Path traversal ('..') is blocked."
            )


        if any(
            ":" in part
            for part in parts
        ):

            raise SandboxViolation(
                (
                    "Drive-qualified paths and alternate "
                    "data streams are blocked."
                )
            )


        return parts


    def _is_link_or_junction(
        self,
        path: Path,
    ) -> bool:
        """
        Block symbolic links and, when supported by the current
        Python version, Windows junctions.
        """

        if path.is_symlink():
            return True


        is_junction = getattr(
            path,
            "is_junction",
            None,
        )


        if callable(is_junction):

            try:

                if is_junction():
                    return True

            except OSError:
                return True


        return False


    def resolve(
        self,
        raw: str,
    ) -> Path:
        """
        Convert a user-supplied relative path into an absolute
        sandbox path while enforcing the sandbox boundary.
        """

        parts = self._parts(
            raw
        )


        current = self.root


        for part in parts:

            current = (
                current
                / part
            )


            if (
                current.exists()
                and self._is_link_or_junction(
                    current
                )
            ):

                raise SandboxViolation(
                    (
                        "Symbolic links and junctions "
                        "are blocked inside the v0.4 sandbox."
                    )
                )


        candidate = (
            self.root
            .joinpath(*parts)
            .resolve(
                strict=False
            )
        )


        if (
            candidate != self.root
            and self.root
            not in candidate.parents
        ):

            raise SandboxViolation(
                "Resolved path escapes the authorized sandbox."
            )


        if (
            candidate == self.trash
            or self.trash in candidate.parents
        ):

            raise SandboxViolation(
                (
                    "Direct access to the quarantine "
                    "directory is blocked."
                )
            )


        return candidate


    def relative(
        self,
        path: Path,
    ) -> str:

        relative = path.relative_to(
            self.root
        )


        return (
            "."
            if str(relative) == "."
            else relative.as_posix()
        )


    # ---------------------------------------------------------
    # SAFE READ OPERATIONS
    # ---------------------------------------------------------

    def list_dir(
        self,
        raw: str = "",
    ) -> list[dict]:

        target = self.resolve(
            raw
        )


        if not target.exists():

            raise FileNotFoundError(
                self.relative(target)
            )


        if not target.is_dir():

            raise NotADirectoryError(
                self.relative(target)
            )


        items = []


        for child in sorted(
            target.iterdir(),
            key=lambda item: (
                not item.is_dir(),
                item.name.lower(),
            ),
        ):

            if (
                child == self.trash
                or child.name == ".nexo_trash"
            ):

                continue


            if self._is_link_or_junction(
                child
            ):

                continue


            stat = child.stat()


            items.append(
                {
                    "name":
                        child.name,

                    "path":
                        self.relative(child),

                    "type":
                        (
                            "directory"
                            if child.is_dir()
                            else "file"
                        ),

                    "size":
                        (
                            stat.st_size
                            if child.is_file()
                            else None
                        ),
                }
            )


        return items


    def read_text(
        self,
        raw: str,
    ) -> dict:

        target = self.resolve(
            raw
        )


        if not target.exists():

            raise FileNotFoundError(
                self.relative(target)
            )


        if not target.is_file():

            raise IsADirectoryError(
                self.relative(target)
            )


        size = (
            target
            .stat()
            .st_size
        )


        if size > MAX_READ_BYTES:

            raise SandboxViolation(
                (
                    f"File exceeds the "
                    f"{MAX_READ_BYTES}-byte read limit."
                )
            )


        try:

            content = target.read_text(
                encoding="utf-8"
            )

        except UnicodeDecodeError as exc:

            raise SandboxViolation(
                (
                    "NEXO v0.4 reads UTF-8 "
                    "text files only."
                )
            ) from exc


        return {
            "path":
                self.relative(target),

            "size":
                size,

            "content":
                content,
        }


    # ---------------------------------------------------------
    # STATE-CHANGING OPERATIONS
    # ---------------------------------------------------------

    def write_text(
        self,
        raw: str,
        content: str,
    ) -> dict:

        data = content.encode(
            "utf-8"
        )


        if len(data) > MAX_WRITE_BYTES:

            raise SandboxViolation(
                (
                    f"Write exceeds the "
                    f"{MAX_WRITE_BYTES}-byte limit."
                )
            )


        target = self.resolve(
            raw
        )


        if (
            target.exists()
            and target.is_dir()
        ):

            raise IsADirectoryError(
                self.relative(target)
            )


        parent = target.parent


        if (
            not parent.exists()
            or not parent.is_dir()
        ):

            raise FileNotFoundError(
                "Parent directory does not exist."
            )


        if self._is_link_or_junction(
            parent
        ):

            raise SandboxViolation(
                "Cannot write through a link or junction."
            )


        fd, temp_name = (
            tempfile.mkstemp(
                prefix=".nexo_tmp_",
                dir=str(parent),
            )
        )


        try:

            with os.fdopen(
                fd,
                "wb",
            ) as temporary:

                temporary.write(
                    data
                )

                temporary.flush()

                os.fsync(
                    temporary.fileno()
                )


            Path(
                temp_name
            ).replace(
                target
            )


        finally:

            temp = Path(
                temp_name
            )


            if temp.exists():

                temp.unlink(
                    missing_ok=True
                )


        return {
            "path":
                self.relative(target),

            "bytes_written":
                len(data),
        }


    def mkdir(
        self,
        raw: str,
    ) -> dict:

        target = self.resolve(
            raw
        )


        if target.exists():

            raise FileExistsError(
                self.relative(target)
            )


        parent = target.parent


        if (
            not parent.exists()
            or not parent.is_dir()
        ):

            raise FileNotFoundError(
                "Parent directory does not exist."
            )


        if self._is_link_or_junction(
            parent
        ):

            raise SandboxViolation(
                (
                    "Cannot create a directory "
                    "through a link or junction."
                )
            )


        target.mkdir()


        return {
            "path":
                self.relative(target),

            "created":
                True,
        }


    # ---------------------------------------------------------
    # SAFE DELETION
    # ---------------------------------------------------------

    def quarantine(
        self,
        raw: str,
    ) -> dict:
        """
        Move a file or directory into NEXO quarantine instead
        of permanently deleting it.
        """

        target = self.resolve(
            raw
        )


        if not target.exists():

            raise FileNotFoundError(
                self.relative(target)
            )


        if target == self.root:

            raise SandboxViolation(
                "The sandbox root cannot be removed."
            )


        if self._is_link_or_junction(
            target
        ):

            raise SandboxViolation(
                (
                    "Links and junctions cannot "
                    "be quarantined."
                )
            )


        original_path = self.relative(
            target
        )


        quarantine_name = (
            f"{uuid.uuid4().hex}_"
            f"{target.name}"
        )


        destination = (
            self.trash
            / quarantine_name
        )


        shutil.move(
            str(target),
            str(destination),
        )


        return {
            "path":
                original_path,

            "quarantined":
                True,

            "quarantine_id":
                quarantine_name,
        }
