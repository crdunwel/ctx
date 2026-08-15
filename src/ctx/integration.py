from __future__ import annotations

import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .diagnostics import CtxError, UnsafePathError
from .discovery import find_project_root
from .paths import absolute_lexical


_HOOKS_FILE_NAME = "hooks.json"
_CODEX_DIRECTORY_NAME = ".codex"

_CODEX_HOOKS = {
    "description": "Automatic .ctx hydration and reconciliation.",
    "hooks": {
        "UserPromptSubmit": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "ctx hook codex-prompt",
                        "timeout": 15,
                        "additionalContextLimit": 6000,
                        "statusMessage": "Hydrating project context",
                    }
                ]
            }
        ],
        "Stop": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "ctx hook codex-stop",
                        "timeout": 30,
                        "statusMessage": "Checking .ctx freshness",
                    }
                ]
            }
        ],
    },
}


@dataclass(frozen=True, slots=True)
class CodexHooksInstallResult:
    action: Literal["created", "unchanged"]
    path: Path
    scope: Literal["project", "user"]
    project_root: Path | None = None
    directory_created: bool = False
    base_identity: tuple[int, int] | None = None
    directory_identity: tuple[int, int] | None = None
    file_identity: tuple[int, int] | None = None
    file_signature: tuple[int, int, int] | None = None


def _canonical_hooks() -> bytes:
    return (
        json.dumps(
            _CODEX_HOOKS,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_base_directory(path: Path) -> int:
    if path.is_symlink():
        raise UnsafePathError(
            "integration.base-symlink",
            f"Codex hook installation base cannot be a symlink: {path}",
        )
    if not path.exists():
        raise CtxError(
            "integration.base-not-found",
            f"Codex hook installation base does not exist: {path}",
            exit_code=1,
        )
    if not path.is_dir():
        raise UnsafePathError(
            "integration.base-not-directory",
            f"Codex hook installation base is not a directory: {path}",
        )
    try:
        descriptor = os.open(path, _directory_flags())
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise UnsafePathError(
                "integration.base-not-directory",
                f"Codex hook installation base is not a directory: {path}",
            )
        return descriptor
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "integration.base-open-failed",
            f"cannot safely open Codex hook installation base {path}: {exc}",
            exit_code=4,
        ) from exc


def _open_or_create_codex_directory(base_fd: int, path: Path) -> tuple[int, bool]:
    created = False
    created_identity: tuple[int, int] | None = None
    try:
        try:
            metadata = os.stat(
                _CODEX_DIRECTORY_NAME,
                dir_fd=base_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            try:
                os.mkdir(_CODEX_DIRECTORY_NAME, mode=0o755, dir_fd=base_fd)
                created = True
                created_metadata = os.stat(
                    _CODEX_DIRECTORY_NAME,
                    dir_fd=base_fd,
                    follow_symlinks=False,
                )
                if not stat.S_ISDIR(created_metadata.st_mode):
                    raise UnsafePathError(
                        "integration.codex-directory-changed",
                        f"new Codex hook directory changed during creation: {path}",
                    )
                created_identity = (
                    created_metadata.st_dev,
                    created_metadata.st_ino,
                )
            except FileExistsError:
                pass
        else:
            if stat.S_ISLNK(metadata.st_mode):
                raise UnsafePathError(
                    "integration.codex-directory-symlink",
                    f"Codex hook directory cannot be a symlink: {path}",
                )
            if not stat.S_ISDIR(metadata.st_mode):
                raise UnsafePathError(
                    "integration.codex-directory-not-directory",
                    f"Codex hook directory is not a directory: {path}",
                )

        descriptor = os.open(
            _CODEX_DIRECTORY_NAME,
            _directory_flags(),
            dir_fd=base_fd,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise UnsafePathError(
                "integration.codex-directory-not-directory",
                f"Codex hook directory is not a directory: {path}",
            )
        if created_identity is not None and created_identity != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            os.close(descriptor)
            raise UnsafePathError(
                "integration.codex-directory-changed",
                f"new Codex hook directory changed before it was opened: {path}",
            )
        return descriptor, created
    except CtxError:
        if created:
            try:
                os.rmdir(_CODEX_DIRECTORY_NAME, dir_fd=base_fd)
            except OSError:
                pass
        raise
    except OSError as exc:
        if created:
            try:
                os.rmdir(_CODEX_DIRECTORY_NAME, dir_fd=base_fd)
            except OSError:
                pass
        raise CtxError(
            "integration.codex-directory-failed",
            f"cannot safely create or open Codex hook directory {path}: {exc}",
            exit_code=4,
        ) from exc


def _read_existing(parent_fd: int, path: Path, expected: bytes) -> str | None:
    try:
        metadata = os.stat(
            _HOOKS_FILE_NAME,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CtxError(
            "integration.hooks-read-failed",
            f"cannot inspect existing Codex hooks file {path}: {exc}",
            exit_code=4,
        ) from exc

    if stat.S_ISLNK(metadata.st_mode):
        raise UnsafePathError(
            "integration.hooks-symlink",
            f"Codex hooks file cannot be a symlink: {path}",
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise UnsafePathError(
            "integration.hooks-not-file",
            f"Codex hooks path is not a regular file: {path}",
        )
    if metadata.st_size != len(expected):
        return "different"

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(_HOOKS_FILE_NAME, flags, dir_fd=parent_fd)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise UnsafePathError(
                    "integration.hooks-not-file",
                    f"Codex hooks path is not a regular file: {path}",
                )
            chunks: list[bytes] = []
            remaining = len(expected) + 1
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            current = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "integration.hooks-read-failed",
            f"cannot safely read existing Codex hooks file {path}: {exc}",
            exit_code=4,
        ) from exc

    if (
        (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        or current.st_size != opened.st_size
        or current.st_mtime_ns != opened.st_mtime_ns
    ):
        raise CtxError(
            "integration.hooks-changed",
            f"Codex hooks file changed while it was inspected: {path}",
            exit_code=4,
        )
    return "same" if b"".join(chunks) == expected else "different"


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:  # pragma: no cover - defensive OS boundary
            raise OSError("short write while publishing Codex hooks")
        remaining = remaining[written:]


def _hook_file_state(parent_fd: int, path: Path) -> tuple[int, int, int, int, int]:
    try:
        metadata = os.stat(
            _HOOKS_FILE_NAME,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise CtxError(
            "integration.hooks-read-failed",
            f"cannot inspect Codex hooks file {path}: {exc}",
            exit_code=4,
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise UnsafePathError(
            "integration.hooks-not-file",
            f"Codex hooks path is not a regular file: {path}",
        )
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _publish_hooks(
    parent_fd: int, path: Path, content: bytes
) -> tuple[Literal["created", "unchanged"], tuple[int, int, int, int, int]]:
    existing = _read_existing(parent_fd, path, content)
    if existing == "same":
        return "unchanged", _hook_file_state(parent_fd, path)
    if existing == "different":
        raise CtxError(
            "integration.hooks-conflict",
            f"Codex hooks file already exists with different content and was not replaced: {path}",
            exit_code=1,
        )

    temporary_name = f".hooks.json.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    descriptor = -1
    published_identity: tuple[int, int] | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_name, flags, 0o644, dir_fd=parent_fd)
        _write_all(descriptor, content)
        os.fsync(descriptor)
        temporary_metadata = os.fstat(descriptor)
        published_identity = (
            temporary_metadata.st_dev,
            temporary_metadata.st_ino,
        )
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(
                temporary_name,
                _HOOKS_FILE_NAME,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            raced = _read_existing(parent_fd, path, content)
            if raced == "same":
                return "unchanged", _hook_file_state(parent_fd, path)
            if raced == "different":
                raise CtxError(
                    "integration.hooks-conflict",
                    f"Codex hooks file appeared with different content and was not replaced: {path}",
                    exit_code=1,
                )
            raise CtxError(
                "integration.hooks-publish-failed",
                f"Codex hooks file could not be published safely: {path}",
                exit_code=4,
            )
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            try:
                current = _hook_file_state(parent_fd, path)
                if published_identity == current[:2]:
                    os.unlink(_HOOKS_FILE_NAME, dir_fd=parent_fd)
            except (CtxError, OSError):
                pass
            raise CtxError(
                "integration.hooks-write-failed",
                f"cannot durably publish Codex hooks file {path}: {exc}",
                exit_code=4,
            ) from exc
        state = _hook_file_state(parent_fd, path)
        if published_identity != state[:2]:
            raise CtxError(
                "integration.hooks-changed",
                f"Codex hooks changed while they were published: {path}",
                exit_code=4,
            )
        return "created", state
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "integration.hooks-write-failed",
            f"cannot publish Codex hooks file {path}: {exc}",
            exit_code=4,
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def install_codex_hooks(
    *, project: Path | None = None, user: bool = False
) -> CodexHooksInstallResult:
    """Create the canonical Codex hook configuration without replacing user data."""

    if user and project is not None:
        raise CtxError(
            "integration.mode-conflict",
            "project and user Codex hook installation targets are mutually exclusive",
            exit_code=1,
        )

    project_root: Path | None
    if user:
        project_root = None
        base = absolute_lexical(Path.home())
        scope: Literal["project", "user"] = "user"
    else:
        project_root, _project_identity = find_project_root(project or Path.cwd())
        base = project_root
        scope = "project"

    target_directory = base / _CODEX_DIRECTORY_NAME
    target = target_directory / _HOOKS_FILE_NAME
    base_fd = _open_base_directory(base)
    parent_fd: int | None = None
    directory_created = False
    base_identity: tuple[int, int] | None = None
    directory_identity: tuple[int, int] | None = None
    file_identity: tuple[int, int] | None = None
    file_signature: tuple[int, int, int] | None = None
    try:
        parent_fd, directory_created = _open_or_create_codex_directory(
            base_fd, target_directory
        )
        base_metadata = os.fstat(base_fd)
        directory_metadata = os.fstat(parent_fd)
        action, file_state = _publish_hooks(parent_fd, target, _canonical_hooks())
        base_identity = (base_metadata.st_dev, base_metadata.st_ino)
        directory_identity = (directory_metadata.st_dev, directory_metadata.st_ino)
        file_identity = file_state[:2]
        file_signature = file_state[2:]
    except Exception:
        if parent_fd is not None:
            os.close(parent_fd)
            parent_fd = None
        if directory_created:
            try:
                os.rmdir(_CODEX_DIRECTORY_NAME, dir_fd=base_fd)
            except OSError:
                pass
        raise
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        os.close(base_fd)
    return CodexHooksInstallResult(
        action,
        target,
        scope,
        project_root,
        directory_created,
        base_identity,
        directory_identity,
        file_identity,
        file_signature,
    )


def remove_created_codex_hooks(result: CodexHooksInstallResult) -> None:
    """Roll back only the exact canonical project hook created by this call."""

    if result.action != "created":
        return
    base = result.project_root or result.path.parent.parent
    expected = _canonical_hooks()
    base_fd = _open_base_directory(base)
    parent_fd: int | None = None
    try:
        base_metadata = os.fstat(base_fd)
        if result.base_identity != (base_metadata.st_dev, base_metadata.st_ino):
            raise CtxError(
                "integration.rollback-failed",
                f"Codex hook installation base changed before rollback: {base}",
                exit_code=4,
            )
        try:
            parent_fd = os.open(
                _CODEX_DIRECTORY_NAME,
                _directory_flags(),
                dir_fd=base_fd,
            )
        except OSError as exc:
            raise CtxError(
                "integration.rollback-failed",
                f"cannot reopen newly created Codex hook directory {result.path.parent}: {exc}",
                exit_code=4,
            ) from exc
        directory_metadata = os.fstat(parent_fd)
        if result.directory_identity != (
            directory_metadata.st_dev,
            directory_metadata.st_ino,
        ):
            raise CtxError(
                "integration.rollback-failed",
                f"Codex hook directory changed before rollback: {result.path.parent}",
                exit_code=4,
            )
        try:
            file_state = _hook_file_state(parent_fd, result.path)
        except CtxError as exc:
            raise CtxError(
                "integration.rollback-failed",
                f"cannot verify newly created Codex hooks before rollback: {result.path}",
                exit_code=4,
            ) from exc
        if (
            result.file_identity != file_state[:2]
            or result.file_signature != file_state[2:]
        ):
            raise CtxError(
                "integration.rollback-failed",
                f"new Codex hooks changed concurrently and were not removed: {result.path}",
                exit_code=4,
            )
        try:
            existing = _read_existing(parent_fd, result.path, expected)
        except CtxError as exc:
            raise CtxError(
                "integration.rollback-failed",
                f"cannot verify newly created Codex hooks before rollback: {result.path}",
                exit_code=4,
            ) from exc
        if existing != "same":
            raise CtxError(
                "integration.rollback-failed",
                f"new Codex hooks changed concurrently and were not removed: {result.path}",
                exit_code=4,
            )
        try:
            current = _hook_file_state(parent_fd, result.path)
        except CtxError as exc:
            raise CtxError(
                "integration.rollback-failed",
                f"cannot verify newly created Codex hooks before removal: {result.path}",
                exit_code=4,
            ) from exc
        if (
            result.file_identity != current[:2]
            or result.file_signature != current[2:]
        ):
            raise CtxError(
                "integration.rollback-failed",
                f"new Codex hooks changed concurrently and were not removed: {result.path}",
                exit_code=4,
            )
        try:
            os.unlink(_HOOKS_FILE_NAME, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except OSError as exc:
            raise CtxError(
                "integration.rollback-failed",
                f"cannot remove newly created Codex hooks {result.path}: {exc}",
                exit_code=4,
            ) from exc
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        if result.directory_created:
            try:
                os.rmdir(_CODEX_DIRECTORY_NAME, dir_fd=base_fd)
            except OSError:
                pass
        os.close(base_fd)
