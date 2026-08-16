from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import posixpath
import secrets
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

try:  # Directory advisory locks are unavailable on Windows.
    import fcntl
except ImportError:  # pragma: no cover - Windows compatibility
    fcntl = None  # type: ignore[assignment]

from .diagnostics import CtxError, UnsafePathError
from .models import LoadedNode
from .paths import is_secret_path, is_within, resolved_project_path
from .retrofit import (
    MAX_FILES,
    RetrofitInventory,
    _open_child_directory_no_follow,
    _open_directory_no_follow,
    inventory_evidence_reasons,
    inventory_repository,
)
from .validation import ValidationResult, validate_project


LOCK_SCHEMA = "ctx-lock/v1"
MAX_LOCK_BYTES = 4_194_304


@dataclass(frozen=True, slots=True)
class Fingerprints:
    source: str
    context: str
    files: int


@dataclass(frozen=True, slots=True)
class NodeStatus:
    uri: str
    manifest: Path
    state: str
    source_fingerprint: str
    context_fingerprint: str
    locked_source_fingerprint: str | None
    locked_context_fingerprint: str | None
    files: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "uri": self.uri,
            "manifest": str(self.manifest),
            "state": self.state,
            "source_fingerprint": self.source_fingerprint,
            "context_fingerprint": self.context_fingerprint,
            "locked_source_fingerprint": self.locked_source_fingerprint,
            "locked_context_fingerprint": self.locked_context_fingerprint,
            "files": self.files,
        }


@dataclass(frozen=True, slots=True)
class ProjectStatus:
    input_path: Path
    root: Path
    project_id: str
    lock_path: Path
    nodes: tuple[NodeStatus, ...]
    validation: ValidationResult
    lock_valid: bool
    lock_error: str | None = None

    @property
    def fresh(self) -> bool:
        return self.validation.valid and self.lock_valid and all(
            node.state == "fresh" for node in self.nodes
        )

    def to_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for node in self.nodes:
            counts[node.state] = counts.get(node.state, 0) + 1
        return {
            "schema": "ctx-status/v1",
            "path": str(self.input_path),
            "project": {"id": self.project_id, "root": str(self.root)},
            "lock": {
                "path": str(self.lock_path),
                "valid": self.lock_valid,
                "error": self.lock_error,
            },
            "fresh": self.fresh,
            "nodes": [node.to_dict() for node in self.nodes],
            "summary": counts,
        }


@dataclass(frozen=True, slots=True)
class LockResult:
    action: str
    path: Path
    status: ProjectStatus
    content: bytes | None = None


@dataclass(frozen=True, slots=True)
class _LockFileState:
    content: bytes
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _LockWriteResult:
    action: str
    content: bytes
    previous: bytes | None


def lock_path(root: Path) -> Path:
    return root / ".ctx" / "lock.json"


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _context_fingerprint(node: LoadedNode) -> str:
    return _sha256(_canonical_json(node.manifest.to_dict()))


def _root_relative_pattern(root: Path, node: LoadedNode, value: str) -> str:
    node_relative = node.document.node_dir.relative_to(root).as_posix()
    joined = posixpath.join(node_relative, value) if node_relative != "." else value
    normalized = posixpath.normpath(joined)
    if normalized == ".." or normalized.startswith("../") or normalized.startswith("/"):
        raise UnsafePathError("path.escape", f"tracking pattern escapes the project: {value}")
    return normalized


def _matches(path: str, pattern: str) -> bool:
    if not any(character in pattern for character in "*?["):
        return path == pattern
    return fnmatch.fnmatchcase(path, pattern) or PurePosixPath(path).match(pattern)


def _tracked_symlinks(root: Path, inventory: RetrofitInventory) -> tuple[str, ...]:
    """Add safe symlink text records without following their targets."""
    candidates: list[str] = []
    eligible_parents = {str(PurePosixPath(value).parent) for value in inventory.eligible_files}
    stack = [root]
    seen = 0
    excluded = {
        ".git",
        ".ctx",
        ".venv",
        "node_modules",
        "vendor",
        "build",
        "dist",
        "target",
        "__pycache__",
    }
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda value: value.name)
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen > MAX_FILES * 4:
                return tuple(candidates)
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                if entry.is_symlink():
                    if not is_secret_path(path, root):
                        candidates.append(relative)
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.casefold() not in excluded and (
                        relative in eligible_parents
                        or any(parent.startswith(relative + "/") for parent in eligible_parents)
                    ):
                        stack.append(path)
            except OSError:
                continue
    return tuple(sorted(set(candidates)))


def _source_record(root_fd: int, relative: str) -> bytes:
    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise UnsafePathError("freshness.unsafe-path", f"unsafe owned path: {relative}")
    parent_fd = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            child_fd = _open_child_directory_no_follow(parent_fd, component)
            os.close(parent_fd)
            parent_fd = child_fd
        before = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            target = os.readlink(parts[-1], dir_fd=parent_fd)
            after = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            if (before.st_dev, before.st_ino, before.st_mtime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_mtime_ns,
            ):
                raise CtxError(
                    "freshness.file-changed",
                    f"symlink changed while fingerprinting: {relative}",
                    exit_code=4,
                )
            digest = hashlib.sha256(target.encode("utf-8", errors="surrogateescape")).hexdigest()
            kind = "symlink"
            metadata = after
        elif stat.S_ISREG(before.st_mode):
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(parts[-1], flags, dir_fd=parent_fd)
            try:
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise CtxError(
                        "freshness.file-changed",
                        f"file changed before fingerprinting: {relative}",
                        exit_code=4,
                    )
                hasher = hashlib.sha256()
                while True:
                    chunk = os.read(descriptor, 1_048_576)
                    if not chunk:
                        break
                    hasher.update(chunk)
                after = os.fstat(descriptor)
                if (
                    (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                    or after.st_size != opened.st_size
                    or after.st_mtime_ns != opened.st_mtime_ns
                ):
                    raise CtxError(
                        "freshness.file-changed",
                        f"file changed while fingerprinting: {relative}",
                        exit_code=4,
                    )
                digest = hasher.hexdigest()
                metadata = after
                kind = "file"
            finally:
                os.close(descriptor)
        else:
            raise UnsafePathError(
                "freshness.unsafe-file", f"owned path is not a regular file: {relative}"
            )
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "freshness.read-failed", f"cannot fingerprint {relative}: {exc}", exit_code=4
        ) from exc
    finally:
        os.close(parent_fd)
    mode = stat.S_IMODE(metadata.st_mode) & 0o111
    return f"{relative}\0{kind}\0{mode:o}\0{digest}\n".encode(
        "utf-8", errors="surrogateescape"
    )


def source_ownership(
    validation: ValidationResult,
    *,
    inventory: RetrofitInventory | None = None,
) -> dict[str, frozenset[str]]:
    """Return deterministic nearest-node source ownership for review routing."""

    root = validation.project_root
    selected_inventory = inventory or inventory_repository(root)
    evidence_reasons = inventory_evidence_reasons(selected_inventory)
    if evidence_reasons:
        reasons = ", ".join(evidence_reasons) or "inventory bound reached"
        raise CtxError(
            "freshness.inventory-partial",
            f"cannot prove freshness from a partial source inventory: {reasons}",
            exit_code=4,
        )
    files = set(selected_inventory.eligible_files)
    files.update(_tracked_symlinks(root, selected_inventory))
    nodes = validation.nodes
    owned: dict[str, set[str]] = {node.uri: set() for node in nodes}
    physical = sorted(
        nodes,
        key=lambda value: len(value.document.node_dir.relative_to(root).parts),
        reverse=True,
    )
    for relative in sorted(files):
        candidate = root / PurePosixPath(relative)
        owner = next(
            (
                node
                for node in physical
                if is_within(candidate, node.document.node_dir)
            ),
            None,
        )
        if owner is not None:
            owned[owner.uri].add(relative)
    for node in nodes:
        for value in node.manifest.tracking.include:
            pattern = _root_relative_pattern(root, node, value)
            owned[node.uri].update(relative for relative in files if _matches(relative, pattern))
        for value in node.manifest.tracking.exclude:
            pattern = _root_relative_pattern(root, node, value)
            owned[node.uri].difference_update(relative for relative in tuple(owned[node.uri]) if _matches(relative, pattern))
        # Every item evidence reference is validated as a top-level artifact,
        # so this single dependency set covers both node artifacts and item
        # evidence without hashing the same file twice. Evidence dependencies
        # outrank tracking excludes.
        for artifact in node.manifest.artifacts:
            resolved = resolved_project_path(
                node.document.node_dir,
                artifact.path,
                root,
                require_exists=True,
            )
            owned[node.uri].add(resolved.relative_to(root).as_posix())
    return {
        uri: frozenset(sorted(paths))
        for uri, paths in sorted(owned.items())
    }


def compute_fingerprints(validation: ValidationResult) -> dict[str, Fingerprints]:
    root = validation.project_root
    inventory = inventory_repository(root)
    owned = source_ownership(validation, inventory=inventory)
    nodes = validation.nodes
    root_fd = _open_directory_no_follow(root)
    if root_fd is None:
        raise CtxError(
            "freshness.platform-unsupported",
            "safe freshness hashing requires no-follow directory descriptors",
            exit_code=4,
        )
    try:
        result: dict[str, Fingerprints] = {}
        for node in nodes:
            source_hasher = hashlib.sha256()
            # A semantic node's physical directory is part of ownership and
            # routing topology even when it currently owns no eligible files.
            # Hash the normalized relative path without storing it in the lock
            # so moving an empty node cannot remain falsely fresh.
            node_relative = node.document.node_dir.relative_to(root).as_posix() or "."
            source_hasher.update(
                f".ctx-node\0{node_relative}\n".encode(
                    "utf-8", errors="surrogateescape"
                )
            )
            for relative in sorted(owned[node.uri]):
                source_hasher.update(_source_record(root_fd, relative))
            result[node.uri] = Fingerprints(
                "sha256:" + source_hasher.hexdigest(),
                _context_fingerprint(node),
                len(owned[node.uri]),
            )
        return result
    finally:
        os.close(root_fd)


def _load_lock(
    root: Path, project_id: str
) -> tuple[dict[str, dict[str, str]], bool, str | None, bytes | None]:
    path = lock_path(root)
    try:
        content = read_lock_bytes_no_follow(path, missing_ok=True)
    except CtxError as exc:
        return {}, False, f"lock is invalid: {exc.message}", None
    if content is None:
        return {}, False, "lock is missing", None
    try:
        raw = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {}, False, f"lock is invalid: {exc}", content
    if (
        type(raw) is not dict
        or set(raw) != {"schema", "project_id", "nodes"}
        or raw.get("schema") != LOCK_SCHEMA
        or raw.get("project_id") != project_id
        or type(raw.get("nodes")) is not dict
    ):
        return {}, False, "lock has an unsupported schema", content
    nodes: dict[str, dict[str, str]] = {}
    for uri, value in raw["nodes"].items():
        if type(uri) is not str or type(value) is not dict:
            return {}, False, "lock node entries are invalid", content
        source = value.get("source_fingerprint")
        context = value.get("context_fingerprint")
        if (
            type(source) is not str
            or type(context) is not str
            or not source.startswith("sha256:")
            or not context.startswith("sha256:")
        ):
            return {}, False, "lock fingerprints are invalid", content
        nodes[uri] = {"source_fingerprint": source, "context_fingerprint": context}
    return nodes, True, None, content


def project_status(path: Path) -> ProjectStatus:
    validation = validate_project(path, strict=True)
    if not validation.valid:
        first = (validation.errors or validation.strict_failures)[0]
        raise CtxError(
            "status.validation-failed",
            f"cannot compute freshness for an invalid project: {first.code}: {first.message}",
            exit_code=3 if validation.unsafe else 1,
        )
    current = compute_fingerprints(validation)
    locked, lock_valid, lock_error, _locked_content = _load_lock(
        validation.project_root, validation.project.id
    )
    statuses: list[NodeStatus] = []
    for node in validation.nodes:
        fingerprint = current[node.uri]
        previous = locked.get(node.uri)
        if previous is None:
            state = "unknown"
            locked_source = None
            locked_context = None
        else:
            locked_source = previous["source_fingerprint"]
            locked_context = previous["context_fingerprint"]
            source_changed = locked_source != fingerprint.source
            context_changed = locked_context != fingerprint.context
            if context_changed:
                state = "context-changed"
            elif source_changed:
                state = "stale"
            else:
                state = "fresh"
        statuses.append(
            NodeStatus(
                node.uri,
                node.document.path,
                state,
                fingerprint.source,
                fingerprint.context,
                locked_source,
                locked_context,
                fingerprint.files,
            )
        )
    extra = sorted(set(locked) - {node.uri for node in validation.nodes})
    if extra:
        lock_valid = False
        lock_error = f"lock contains removed nodes: {', '.join(extra[:4])}"
    return ProjectStatus(
        path.resolve(strict=True),
        validation.project_root,
        validation.project.id,
        lock_path(validation.project_root),
        tuple(statuses),
        validation,
        lock_valid,
        lock_error,
    )


def _lock_state_from_descriptor(descriptor: int, path: Path) -> _LockFileState:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise UnsafePathError("lock.not-regular", f"lock is not a regular file: {path}")
    if before.st_size > MAX_LOCK_BYTES:
        raise CtxError(
            "lock.too-large",
            f"lock exceeds its safety limit: {path}",
            exit_code=4,
        )
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_LOCK_BYTES:
        chunk = os.read(descriptor, min(65_536, MAX_LOCK_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > MAX_LOCK_BYTES:
        raise CtxError(
            "lock.too-large",
            f"lock exceeds its safety limit: {path}",
            exit_code=4,
        )
    after = os.fstat(descriptor)
    before_identity = (
        before.st_dev,
        before.st_ino,
        stat.S_IMODE(before.st_mode),
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        stat.S_IMODE(after.st_mode),
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity:
        raise CtxError(
            "lock.concurrent-change",
            f"freshness lock changed while it was being read: {path}",
            exit_code=4,
        )
    return _LockFileState(
        b"".join(chunks),
        after.st_dev,
        after.st_ino,
        stat.S_IMODE(after.st_mode),
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _read_lock_at(
    directory_fd: int,
    name: str,
    path: Path,
) -> _LockFileState | None:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        try:
            failed_metadata = os.stat(
                name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError:
            failed_metadata = None
        if failed_metadata is not None and stat.S_ISLNK(failed_metadata.st_mode):
            raise UnsafePathError("lock.symlink", f"lock cannot be a symlink: {path}") from exc
        raise CtxError(
            "lock.read-failed",
            f"cannot safely open freshness lock {path}: {exc}",
            exit_code=4,
        ) from exc
    try:
        return _lock_state_from_descriptor(descriptor, path)
    finally:
        os.close(descriptor)


def _read_lock_fallback(path: Path) -> _LockFileState | None:
    """Best available final-component protection where dir_fd is unavailable."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if path.is_symlink():
            raise UnsafePathError("lock.symlink", f"lock cannot be a symlink: {path}") from exc
        raise CtxError(
            "lock.read-failed",
            f"cannot safely open freshness lock {path}: {exc}",
            exit_code=4,
        ) from exc
    try:
        return _lock_state_from_descriptor(descriptor, path)
    finally:
        os.close(descriptor)


def read_lock_bytes_no_follow(path: Path, *, missing_ok: bool = False) -> bytes | None:
    """Read exact lock bytes without following the lock or parent symlinks."""

    try:
        directory_fd = _open_directory_no_follow(path.parent)
    except OSError as exc:
        raise UnsafePathError(
            "lock.parent-unsafe",
            f"cannot safely open freshness lock directory {path.parent}: {exc}",
        ) from exc
    if directory_fd is None:
        state = _read_lock_fallback(path)
    else:
        try:
            state = _read_lock_at(directory_fd, path.name, path)
        finally:
            os.close(directory_fd)
    if state is None and not missing_ok:
        raise CtxError(
            "lock.missing",
            f"freshness lock is missing: {path}",
            exit_code=4,
        )
    return None if state is None else state.content


def _same_lock_state(
    first: _LockFileState | None,
    second: _LockFileState | None,
) -> bool:
    return first == second


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:  # pragma: no cover - defensive OS boundary
            raise OSError("short write while writing freshness lock")
        remaining = remaining[written:]


def _replace_lock_bytes_at(
    directory_fd: int,
    path: Path,
    replacement: bytes | None,
    *,
    expected_previous: bytes | None | object,
    mismatch_code: str,
    mismatch_message: str,
) -> _LockWriteResult:
    if fcntl is not None:
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
    initial = _read_lock_at(directory_fd, path.name, path)
    initial_content = None if initial is None else initial.content
    if expected_previous is not _ANY_LOCK and initial_content != expected_previous:
        raise CtxError(mismatch_code, mismatch_message, exit_code=4)
    if replacement == initial_content:
        return _LockWriteResult("unchanged", replacement or b"", initial_content)

    temporary_name: str | None = None
    temporary_identity: tuple[int, int] | None = None
    try:
        if replacement is not None:
            temporary_name = f".lock.{os.getpid()}.{secrets.token_hex(8)}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
            try:
                _write_all(descriptor, replacement)
                os.fsync(descriptor)
                metadata = os.fstat(descriptor)
                temporary_identity = (metadata.st_dev, metadata.st_ino)
            finally:
                os.close(descriptor)

        current = _read_lock_at(directory_fd, path.name, path)
        if not _same_lock_state(initial, current):
            raise CtxError(mismatch_code, mismatch_message, exit_code=4)

        if replacement is None:
            if current is not None:
                os.unlink(path.name, dir_fd=directory_fd)
            action = "removed"
        else:
            assert temporary_name is not None
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            temporary_name = None
            action = "updated" if initial is not None else "created"
        os.fsync(directory_fd)

        written = _read_lock_at(directory_fd, path.name, path)
        if replacement is None:
            if written is not None:
                raise CtxError(mismatch_code, mismatch_message, exit_code=4)
            return _LockWriteResult(action, b"", initial_content)
        if (
            written is None
            or written.content != replacement
            or temporary_identity != (written.device, written.inode)
        ):
            raise CtxError(mismatch_code, mismatch_message, exit_code=4)
        return _LockWriteResult(action, replacement, initial_content)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass


_ANY_LOCK = object()


def _replace_lock_bytes(
    path: Path,
    replacement: bytes | None,
    *,
    expected_previous: bytes | None | object = _ANY_LOCK,
    mismatch_code: str = "lock.concurrent-change",
    mismatch_message: str | None = None,
) -> _LockWriteResult:
    if replacement is not None and len(replacement) > MAX_LOCK_BYTES:
        raise CtxError(
            "lock.too-large",
            f"refusing to write a freshness lock over the safety limit: {path}",
            exit_code=4,
        )
    message = mismatch_message or f"freshness lock changed concurrently: {path}"
    try:
        directory_fd = _open_directory_no_follow(path.parent)
    except OSError as exc:
        raise UnsafePathError(
            "lock.parent-unsafe",
            f"cannot safely open freshness lock directory {path.parent}: {exc}",
        ) from exc
    if directory_fd is None:  # pragma: no cover - Windows compatibility
        initial = _read_lock_fallback(path)
        initial_content = None if initial is None else initial.content
        if expected_previous is not _ANY_LOCK and initial_content != expected_previous:
            raise CtxError(mismatch_code, message, exit_code=4)
        if replacement == initial_content:
            return _LockWriteResult("unchanged", replacement or b"", initial_content)
        temporary: Path | None = None
        temporary_identity: tuple[int, int] | None = None
        try:
            if replacement is not None:
                descriptor, temporary_name = tempfile.mkstemp(
                    dir=path.parent,
                    prefix=".lock.",
                    suffix=".tmp",
                )
                temporary = Path(temporary_name)
                try:
                    _write_all(descriptor, replacement)
                    os.fsync(descriptor)
                    metadata = os.fstat(descriptor)
                    temporary_identity = (metadata.st_dev, metadata.st_ino)
                finally:
                    os.close(descriptor)
            current = _read_lock_fallback(path)
            if not _same_lock_state(initial, current):
                raise CtxError(mismatch_code, message, exit_code=4)
            if replacement is None:
                path.unlink(missing_ok=True)
                action = "removed"
            else:
                assert temporary is not None
                os.replace(temporary, path)
                temporary = None
                action = "updated" if initial is not None else "created"
            written = _read_lock_fallback(path)
            if replacement is None:
                if written is not None:
                    raise CtxError(mismatch_code, message, exit_code=4)
                return _LockWriteResult(action, b"", initial_content)
            if (
                written is None
                or written.content != replacement
                or temporary_identity != (written.device, written.inode)
            ):
                raise CtxError(mismatch_code, message, exit_code=4)
            return _LockWriteResult(action, replacement, initial_content)
        except CtxError:
            raise
        except OSError as exc:
            raise CtxError(
                "lock.write-failed",
                f"cannot write freshness lock {path}: {exc}",
                exit_code=4,
            ) from exc
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    try:
        return _replace_lock_bytes_at(
            directory_fd,
            path,
            replacement,
            expected_previous=expected_previous,
            mismatch_code=mismatch_code,
            mismatch_message=message,
        )
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "lock.write-failed",
            f"cannot write freshness lock {path}: {exc}",
            exit_code=4,
        ) from exc
    finally:
        os.close(directory_fd)


def _write_lock(
    path: Path,
    payload: dict[str, Any],
    *,
    expected_previous: bytes | None | object = _ANY_LOCK,
    mismatch_code: str = "lock.concurrent-change",
    mismatch_message: str | None = None,
) -> _LockWriteResult:
    return _replace_lock_bytes(
        path,
        _canonical_json(payload),
        expected_previous=expected_previous,
        mismatch_code=mismatch_code,
        mismatch_message=mismatch_message,
    )


def _restore_lock(
    path: Path,
    previous: bytes | None,
    *,
    expected_current: bytes,
) -> None:
    _replace_lock_bytes(
        path,
        previous,
        expected_previous=expected_current,
        mismatch_code="lock.rollback-failed",
        mismatch_message=f"freshness lock changed concurrently and was not restored: {path}",
    )


def seal_freshness(
    path: Path,
    *,
    expected_previous: bytes | None | object = _ANY_LOCK,
    mismatch_code: str = "lock.concurrent-change",
    mismatch_message: str | None = None,
) -> LockResult:
    validation = validate_project(path, strict=True)
    if not validation.valid:
        first = (validation.errors or validation.strict_failures)[0]
        raise CtxError(
            "lock.validation-failed",
            f"strict validation must pass before sealing freshness: {first.code}: {first.message}",
            exit_code=3 if validation.unsafe else 1,
        )
    fingerprints = compute_fingerprints(validation)
    payload = {
        "schema": LOCK_SCHEMA,
        "project_id": validation.project.id,
        "nodes": {
            uri: {
                "source_fingerprint": value.source,
                "context_fingerprint": value.context,
            }
            for uri, value in sorted(fingerprints.items())
        },
    }
    output = lock_path(validation.project_root)
    write = _write_lock(
        output,
        payload,
        expected_previous=expected_previous,
        mismatch_code=mismatch_code,
        mismatch_message=mismatch_message,
    )
    try:
        status = project_status(validation.project_root)
        if not status.fresh:
            raise CtxError(
                "lock.project-changed",
                "project changed while freshness was being sealed; the prior lock was restored",
                exit_code=4,
            )
    except Exception:
        _restore_lock(
            output,
            write.previous,
            expected_current=write.content,
        )
        raise
    return LockResult(write.action, output, status, write.content)


def seal_freshness_subset(
    path: Path,
    uris: Iterable[str],
    *,
    expected_fingerprints: dict[str, tuple[str, str]] | None = None,
) -> LockResult:
    """Refresh only reviewed node entries in an existing valid lock.

    Hook reconciliation must not bless unrelated state that was already stale
    before the active turn began.  This operation therefore replaces (or
    removes) only the explicitly reviewed semantic URIs and preserves every
    other lock entry byte-for-byte at the value level.
    """

    selected = frozenset(uris)
    if not selected:
        raise CtxError(
            "lock.selection-empty",
            "at least one reviewed node URI is required for selective sealing",
            exit_code=1,
        )
    validation = validate_project(path, strict=True)
    if not validation.valid:
        first = (validation.errors or validation.strict_failures)[0]
        raise CtxError(
            "lock.validation-failed",
            f"strict validation must pass before sealing freshness: {first.code}: {first.message}",
            exit_code=3 if validation.unsafe else 1,
        )
    current = compute_fingerprints(validation)
    if expected_fingerprints is not None and {
        uri: (value.source, value.context) for uri, value in current.items()
    } != expected_fingerprints:
        raise CtxError(
            "lock.project-changed",
            "project changed after reconciliation review and before freshness sealing",
            exit_code=4,
        )
    locked, lock_valid, lock_error, locked_content = _load_lock(
        validation.project_root, validation.project.id
    )
    output = lock_path(validation.project_root)
    if not lock_valid and lock_error == "lock is missing" and not output.is_symlink():
        # A run baseline can safely initialize only its reviewed entries. Other
        # nodes remain unknown rather than being implicitly blessed.
        locked = {}
        lock_valid = True
    if not lock_valid:
        raise CtxError(
            "lock.reconciliation-required",
            "selective reconciliation requires an existing valid lock: "
            f"{lock_error or 'lock is invalid'}",
            exit_code=1,
        )
    known = set(current) | set(locked)
    unknown = sorted(selected - known)
    if unknown:
        raise CtxError(
            "lock.selection-unknown",
            f"reviewed node is not present in the project or lock: {unknown[0]}",
            exit_code=1,
        )

    updated = {uri: dict(value) for uri, value in locked.items()}
    for uri in sorted(selected):
        fingerprint = current.get(uri)
        if fingerprint is None:
            updated.pop(uri, None)
        else:
            updated[uri] = {
                "source_fingerprint": fingerprint.source,
                "context_fingerprint": fingerprint.context,
            }
    payload = {
        "schema": LOCK_SCHEMA,
        "project_id": validation.project.id,
        "nodes": {uri: updated[uri] for uri in sorted(updated)},
    }
    write = _write_lock(
        output,
        payload,
        expected_previous=locked_content,
        mismatch_code="lock.concurrent-change",
        mismatch_message=(
            "freshness lock changed after selective reconciliation loaded it"
        ),
    )
    try:
        verified_validation = validate_project(validation.project_root, strict=True)
        if not verified_validation.valid:
            raise CtxError(
                "lock.project-changed",
                "project validation changed while reviewed freshness was being sealed",
                exit_code=4,
            )
        verified = compute_fingerprints(verified_validation)
        for uri in selected:
            expected = current.get(uri)
            actual = verified.get(uri)
            if expected != actual:
                raise CtxError(
                    "lock.project-changed",
                    "project changed while reviewed freshness was being sealed; "
                    "the prior lock was restored",
                    exit_code=4,
                )
        reloaded, reloaded_valid, reloaded_error, _reloaded_content = _load_lock(
            validation.project_root, validation.project.id
        )
        if not reloaded_valid:
            raise CtxError(
                "lock.write-invalid",
                f"selective freshness lock did not validate: {reloaded_error}",
                exit_code=4,
            )
        for uri in selected:
            expected = updated.get(uri)
            if reloaded.get(uri) != expected:
                raise CtxError(
                    "lock.write-invalid",
                    "selective freshness lock did not preserve the reviewed entries",
                    exit_code=4,
                )
        status = project_status(validation.project_root)
    except Exception:
        _restore_lock(
            output,
            write.previous,
            expected_current=write.content,
        )
        raise
    return LockResult(write.action, output, status, write.content)


def initialize_freshness(path: Path) -> LockResult:
    """Create the first lock, but never bless an already-stale project."""
    validation = validate_project(path, strict=True)
    output = lock_path(validation.project_root)
    if output.exists() or output.is_symlink():
        status = project_status(validation.project_root)
        if status.fresh:
            content = read_lock_bytes_no_follow(output)
            assert content is not None
            return LockResult("unchanged", output, status, content)
        raise CtxError(
            "lock.reconciliation-required",
            "an existing freshness lock is not fresh; use `ctx reconcile` rather "
            "than retrofit to review and seal the changes",
            exit_code=1,
        )
    return seal_freshness(
        path,
        expected_previous=None,
        mismatch_code="lock.concurrent-change",
        mismatch_message="freshness lock appeared during initialization",
    )


def remove_created_lock(result: LockResult, expected_bytes: bytes) -> None:
    """Best-effort exact rollback used by the retrofit transaction."""
    if result.action != "created":
        return
    try:
        _replace_lock_bytes(
            result.path,
            None,
            expected_previous=expected_bytes,
            mismatch_code="lock.rollback-failed",
            mismatch_message=(
                "new lock changed concurrently and was not removed: "
                f"{result.path}"
            ),
        )
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "lock.rollback-failed",
            f"cannot roll back new freshness lock {result.path}: {exc}",
            exit_code=4,
        ) from exc


def restore_replaced_lock(
    result: LockResult,
    expected_bytes: bytes,
    previous_bytes: bytes,
) -> None:
    """Restore an exactly known lock replaced by a guarded transaction."""

    if result.action != "updated":
        return
    try:
        _restore_lock(
            result.path,
            previous_bytes,
            expected_current=expected_bytes,
        )
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "lock.rollback-failed",
            f"cannot restore replaced freshness lock {result.path}: {exc}",
            exit_code=4,
        ) from exc
