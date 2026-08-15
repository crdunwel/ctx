from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from .diagnostics import CtxError, NotFoundError, UnsafePathError
from .discovery import discover_ancestry, find_project_root
from .freshness import Fingerprints, compute_fingerprints, project_status
from .paths import is_secret_path, is_within
from .registry import ctx_home
from .validation import validate_project


RUN_SCHEMA = "ctx-run/v2"
MAX_RUN_BYTES = 4_194_304
MAX_RUNS_PER_PROJECT = 10_000
MAX_GLOBAL_RUNS = 50_000
MAX_TASK_CHARACTERS = 32_000
MAX_DIRTY_PATHS = 2_000
RUN_ID_PATTERN = re.compile(r"^[a-f0-9]{32}$")


@dataclass(frozen=True, slots=True)
class RunFingerprint:
    source: str
    context: str

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "context": self.context}


@dataclass(frozen=True, slots=True)
class RunAcknowledgement:
    uri: str
    reason: str
    fingerprint: RunFingerprint | None


@dataclass(frozen=True, slots=True)
class RunRecord:
    run_id: str
    project_root: Path
    project_id: str
    starting_path: Path
    starting_uri: str
    task_digest: str
    session_id: str | None
    turn_ids: tuple[str, ...]
    baseline_nodes: dict[str, RunFingerprint]
    baseline_node_states: dict[str, str]
    baseline_git_head: str | None
    baseline_dirty_files: dict[str, str | None]
    baseline_limitation: str | None
    acknowledgements: tuple[RunAcknowledgement, ...]
    continuation_count: int
    status: Literal["active", "complete", "incomplete-allowed"]
    completion_nodes: dict[str, RunFingerprint]
    path: Path

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": RUN_SCHEMA,
            "run_id": self.run_id,
            "project_root": str(self.project_root),
            "project_id": self.project_id,
            "starting_path": str(self.starting_path),
            "starting_uri": self.starting_uri,
            "task_digest": self.task_digest,
            "session_id": self.session_id,
            "turn_ids": list(self.turn_ids),
            "baseline": {
                "nodes": {
                    uri: value.to_dict()
                    for uri, value in sorted(self.baseline_nodes.items())
                },
                "node_states": {
                    uri: self.baseline_node_states[uri]
                    for uri in sorted(self.baseline_node_states)
                },
                "git_head": self.baseline_git_head,
                "dirty_files": {
                    key: self.baseline_dirty_files[key]
                    for key in sorted(self.baseline_dirty_files)
                },
                "limitation": self.baseline_limitation,
            },
            "acknowledgements": [
                {
                    "uri": value.uri,
                    "reason": value.reason,
                    "fingerprint": (
                        None if value.fingerprint is None else value.fingerprint.to_dict()
                    ),
                }
                for value in self.acknowledgements
            ],
            "continuation_count": self.continuation_count,
            "status": self.status,
            "completion_nodes": {
                uri: value.to_dict()
                for uri, value in sorted(self.completion_nodes.items())
            },
        }


@dataclass(frozen=True, slots=True)
class RunNodeChange:
    uri: str
    source_changed: bool
    context_changed: bool
    added: bool
    removed: bool
    manifest: Path | None

    @property
    def requires_acknowledgement(self) -> bool:
        return self.source_changed and not self.context_changed

    def to_dict(self) -> dict[str, Any]:
        return {
            "uri": self.uri,
            "source_changed": self.source_changed,
            "context_changed": self.context_changed,
            "added": self.added,
            "removed": self.removed,
            "manifest": None if self.manifest is None else str(self.manifest),
        }


@dataclass(frozen=True, slots=True)
class RunPathChange:
    path: str
    baseline_hash: str | None
    current_hash: str | None
    preexisting_at_start: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "baseline_hash": self.baseline_hash,
            "current_hash": self.current_hash,
            "preexisting_at_start": self.preexisting_at_start,
        }


def _project_key(root: Path) -> str:
    return hashlib.sha256(os.fsencode(str(root))).hexdigest()[:32]


def _runs_root() -> Path:
    return ctx_home() / "runs"


def _project_run_dir(root: Path) -> Path:
    return _runs_root() / _project_key(root)


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_named_directory(
    parent_fd: int,
    name: str,
    display_path: Path,
    *,
    create: bool,
) -> int:
    try:
        try:
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            if not create:
                raise
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise UnsafePathError(
                "run.directory-unsafe",
                f"run directory is unsafe: {display_path}",
            )
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode):
            os.close(descriptor)
            raise UnsafePathError(
                "run.directory-unsafe",
                f"run directory is unsafe: {display_path}",
            )
        return descriptor
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "run.directory-failed",
            f"cannot safely open run directory {display_path}: {exc}",
            exit_code=4,
        ) from exc


def _open_runs_root(*, create: bool) -> int:
    home = ctx_home()
    if create:
        try:
            home.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise CtxError(
                "run.directory-failed",
                f"cannot create CTX_HOME for run state: {exc}",
                exit_code=4,
            ) from exc
    if not home.exists():
        raise FileNotFoundError(home)
    if home.is_symlink() or not home.is_dir():
        raise UnsafePathError(
            "run.home-symlink",
            f"CTX_HOME must be a real directory: {home}",
        )
    try:
        home_fd = os.open(home, _directory_flags())
    except OSError as exc:
        raise CtxError(
            "run.directory-failed",
            f"cannot safely open CTX_HOME: {exc}",
            exit_code=4,
        ) from exc
    try:
        return _open_named_directory(
            home_fd,
            "runs",
            home / "runs",
            create=create,
        )
    finally:
        os.close(home_fd)


def _open_project_run_directory(root: Path, *, create: bool) -> int:
    runs_fd = _open_runs_root(create=create)
    try:
        return _open_named_directory(
            runs_fd,
            _project_key(root),
            _project_run_dir(root),
            create=create,
        )
    finally:
        os.close(runs_fd)


def _validate_identifier(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    if not value or len(value) > 512 or any(ord(character) < 32 for character in value):
        raise CtxError("run.identifier-invalid", f"{label} is invalid", exit_code=1)
    return value


def _fingerprints(value: dict[str, Fingerprints]) -> dict[str, RunFingerprint]:
    return {
        uri: RunFingerprint(fingerprint.source, fingerprint.context)
        for uri, fingerprint in value.items()
    }


def current_run_fingerprints(root: Path) -> dict[str, RunFingerprint]:
    validation = validate_project(root, strict=True)
    if not validation.valid:
        first = (validation.errors or validation.strict_failures)[0]
        raise CtxError(
            "run.validation-failed",
            f"cannot compare a run against invalid context: {first.code}: {first.message}",
            exit_code=3 if validation.unsafe else 1,
        )
    return _fingerprints(compute_fingerprints(validation))


def _git_output(root: Path, arguments: list[str], *, maximum: int = 4_194_304) -> bytes | None:
    try:
        process = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-C", str(root), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if process.returncode != 0 or len(process.stdout) > maximum:
        return None
    return process.stdout


def _hash_dirty_file(root: Path, relative: str) -> str | None:
    candidate = root / PurePosixPath(relative)
    if not is_within(candidate, root) or is_secret_path(candidate, root):
        return None
    try:
        before = candidate.lstat()
        if not stat.S_ISREG(before.st_mode) or candidate.is_symlink():
            return None
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(candidate, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                return None
            hasher = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1_048_576)
                if not chunk:
                    break
                hasher.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
        ):
            return None
        return "sha256:" + hasher.hexdigest()
    except OSError:
        return None


def _git_baseline(root: Path) -> tuple[str | None, dict[str, str | None], str | None]:
    head_raw = _git_output(root, ["rev-parse", "HEAD"], maximum=256)
    if head_raw is None:
        return None, {}, "Git baseline unavailable; node fingerprints preserve the pre-turn state."
    head = head_raw.decode("ascii", errors="ignore").strip() or None
    changed = _git_output(root, ["diff", "--name-only", "-z", "HEAD", "--"])
    untracked = _git_output(root, ["ls-files", "--others", "--exclude-standard", "-z"])
    if changed is None or untracked is None:
        return head, {}, "Per-file dirty attribution unavailable; node fingerprints preserve the pre-turn state."
    paths: set[str] = set()
    for raw in (changed, untracked):
        for encoded in raw.split(b"\0"):
            if not encoded:
                continue
            relative = os.fsdecode(encoded).replace(os.sep, "/")
            parts = PurePosixPath(relative).parts
            if (
                not parts
                or relative.startswith("/")
                or any(part in {"", ".", ".."} for part in parts)
                or relative.startswith(".ctx/")
                or is_secret_path(root / PurePosixPath(relative), root)
            ):
                continue
            paths.add(relative)
    ordered = sorted(paths)
    limitation = None
    if len(ordered) > MAX_DIRTY_PATHS:
        ordered = ordered[:MAX_DIRTY_PATHS]
        limitation = "Dirty-file baseline was truncated; aggregate node fingerprints remain authoritative."
    return head, {path: _hash_dirty_file(root, path) for path in ordered}, limitation


def run_path_changes(run: RunRecord) -> tuple[tuple[RunPathChange, ...], str | None]:
    """Return bounded Git path evidence without retaining file contents.

    Node fingerprints remain authoritative. Path evidence is available only
    while the baseline commit is unchanged; otherwise a checkout or merge can
    make a working-tree-only list incomplete.
    """

    head, current, limitation = _git_baseline(run.project_root)
    if run.baseline_git_head is None or head is None:
        return (), run.baseline_limitation or limitation or (
            "Per-file change attribution is unavailable; inspect affected node source directly."
        )
    if head != run.baseline_git_head:
        return (), (
            "Git HEAD changed during the run; node fingerprints identify affected scopes, "
            "but per-file attribution is intentionally omitted."
        )
    changes = tuple(
        RunPathChange(
            path,
            run.baseline_dirty_files.get(path),
            current.get(path),
            path in run.baseline_dirty_files,
        )
        for path in sorted(set(run.baseline_dirty_files) | set(current))
        if run.baseline_dirty_files.get(path) != current.get(path)
        or (path in run.baseline_dirty_files) != (path in current)
    )
    return changes, limitation or run.baseline_limitation


def _ensure_run_directory(root: Path) -> Path:
    directory = _project_run_dir(root)
    descriptor = _open_project_run_directory(root, create=True)
    os.close(descriptor)
    return directory


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:  # pragma: no cover - defensive OS contract check
            raise OSError("short write while persisting run state")
        offset += written


def _atomic_write(run: RunRecord, content: bytes, *, create: bool = False) -> None:
    if len(content) > MAX_RUN_BYTES:
        raise CtxError("run.too-large", "run state exceeds its safety limit", exit_code=4)
    directory_fd = _open_project_run_directory(run.project_root, create=True)
    temporary_name = f".run.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        try:
            _write_all(descriptor, content)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if create:
            try:
                os.link(
                    temporary_name,
                    run.path.name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise CtxError(
                    "run.collision",
                    f"run already exists: {run.path.stem}",
                    exit_code=4,
                ) from exc
        else:
            try:
                metadata = os.stat(
                    run.path.name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError as exc:
                raise CtxError(
                    "run.not-found",
                    f"run state disappeared before update: {run.run_id}",
                    exit_code=4,
                ) from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise UnsafePathError(
                    "run.symlink",
                    f"run state cannot be a symlink or special file: {run.path}",
                )
            os.replace(
                temporary_name,
                run.path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
        os.fsync(directory_fd)
    finally:
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        finally:
            os.close(directory_fd)


def _parse_fingerprint_map(raw: object, label: str) -> dict[str, RunFingerprint]:
    if type(raw) is not dict:
        raise CtxError("run.invalid", f"{label} must be an object", exit_code=4)
    result: dict[str, RunFingerprint] = {}
    for uri, value in raw.items():
        if type(uri) is not str or type(value) is not dict or set(value) != {"source", "context"}:
            raise CtxError("run.invalid", f"{label} contains an invalid entry", exit_code=4)
        source = value.get("source")
        context = value.get("context")
        if (
            type(source) is not str
            or type(context) is not str
            or not source.startswith("sha256:")
            or not context.startswith("sha256:")
        ):
            raise CtxError("run.invalid", f"{label} contains invalid fingerprints", exit_code=4)
        result[uri] = RunFingerprint(source, context)
    return result


def _parse_run(raw: object, path: Path) -> RunRecord:
    if type(raw) is not dict or raw.get("schema") != RUN_SCHEMA:
        raise CtxError("run.invalid", f"run state has an unsupported schema: {path}", exit_code=4)
    required = {
        "schema", "run_id", "project_root", "project_id", "starting_path",
        "starting_uri", "task_digest", "session_id", "turn_ids", "baseline",
        "acknowledgements", "continuation_count", "status", "completion_nodes",
    }
    if set(raw) != required:
        raise CtxError("run.invalid", f"run state fields are invalid: {path}", exit_code=4)
    run_id = raw["run_id"]
    baseline = raw["baseline"]
    if type(run_id) is not str or not RUN_ID_PATTERN.fullmatch(run_id) or type(baseline) is not dict:
        raise CtxError("run.invalid", f"run identity or baseline is invalid: {path}", exit_code=4)
    if set(baseline) != {"nodes", "node_states", "git_head", "dirty_files", "limitation"}:
        raise CtxError("run.invalid", f"run baseline fields are invalid: {path}", exit_code=4)
    project_root = Path(raw["project_root"])
    starting_path = Path(raw["starting_path"])
    if not project_root.is_absolute() or not starting_path.is_absolute():
        raise CtxError("run.invalid", f"run paths must be absolute: {path}", exit_code=4)
    if type(raw["turn_ids"]) is not list or any(type(value) is not str for value in raw["turn_ids"]):
        raise CtxError("run.invalid", f"run turn IDs are invalid: {path}", exit_code=4)
    dirty = baseline["dirty_files"]
    if type(dirty) is not dict or any(
        type(key) is not str or (value is not None and type(value) is not str)
        for key, value in dirty.items()
    ):
        raise CtxError("run.invalid", f"run dirty baseline is invalid: {path}", exit_code=4)
    node_states = baseline["node_states"]
    if (
        type(node_states) is not dict
        or any(
            type(uri) is not str
            or state not in {"fresh", "stale", "context-changed", "unknown"}
            for uri, state in node_states.items()
        )
    ):
        raise CtxError("run.invalid", f"run baseline node states are invalid: {path}", exit_code=4)
    if baseline["git_head"] is not None and type(baseline["git_head"]) is not str:
        raise CtxError("run.invalid", f"run Git baseline is invalid: {path}", exit_code=4)
    if baseline["limitation"] is not None and type(baseline["limitation"]) is not str:
        raise CtxError("run.invalid", f"run baseline limitation is invalid: {path}", exit_code=4)
    acknowledgements_raw = raw["acknowledgements"]
    if type(acknowledgements_raw) is not list:
        raise CtxError("run.invalid", f"run acknowledgements are invalid: {path}", exit_code=4)
    acknowledgements: list[RunAcknowledgement] = []
    for value in acknowledgements_raw:
        if (
            type(value) is not dict
            or set(value) != {"uri", "reason", "fingerprint"}
            or type(value["uri"]) is not str
            or type(value["reason"]) is not str
        ):
            raise CtxError("run.invalid", f"run acknowledgement is invalid: {path}", exit_code=4)
        if not value["reason"].strip() or len(value["reason"]) > 500:
            raise CtxError("run.invalid", f"run acknowledgement reason is invalid: {path}", exit_code=4)
        fingerprint_raw = value["fingerprint"]
        if fingerprint_raw is None:
            fingerprint = None
        else:
            parsed = _parse_fingerprint_map(
                {value["uri"]: fingerprint_raw},
                "run acknowledgement fingerprint",
            )
            fingerprint = parsed[value["uri"]]
        acknowledgements.append(
            RunAcknowledgement(value["uri"], value["reason"], fingerprint)
        )
    status_value = raw["status"]
    if status_value not in {"active", "complete", "incomplete-allowed"}:
        raise CtxError("run.invalid", f"run status is invalid: {path}", exit_code=4)
    scalar_strings = ("project_id", "starting_uri", "task_digest")
    if any(type(raw[key]) is not str for key in scalar_strings):
        raise CtxError("run.invalid", f"run strings are invalid: {path}", exit_code=4)
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", raw["task_digest"]):
        raise CtxError("run.invalid", f"run task digest is invalid: {path}", exit_code=4)
    session_id = raw["session_id"]
    if session_id is not None and type(session_id) is not str:
        raise CtxError("run.invalid", f"run session ID is invalid: {path}", exit_code=4)
    if type(raw["continuation_count"]) is not int or raw["continuation_count"] < 0:
        raise CtxError("run.invalid", f"run continuation count is invalid: {path}", exit_code=4)
    baseline_nodes = _parse_fingerprint_map(baseline["nodes"], "run baseline nodes")
    if set(node_states) != set(baseline_nodes):
        raise CtxError(
            "run.invalid",
            f"run baseline states do not match baseline nodes: {path}",
            exit_code=4,
        )
    return RunRecord(
        run_id, project_root, raw["project_id"], starting_path, raw["starting_uri"],
        raw["task_digest"], session_id, tuple(raw["turn_ids"]),
        baseline_nodes,
        dict(node_states),
        baseline["git_head"], dict(dirty), baseline["limitation"],
        tuple(acknowledgements), raw["continuation_count"], status_value,
        _parse_fingerprint_map(raw["completion_nodes"], "run completion nodes"), path,
    )


def _read_run(path: Path) -> RunRecord:
    if path.is_symlink():
        raise UnsafePathError("run.symlink", f"run state cannot be a symlink: {path}")
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_RUN_BYTES:
            raise CtxError("run.invalid", f"run state is not a bounded regular file: {path}", exit_code=4)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_size > MAX_RUN_BYTES
                or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
            ):
                raise CtxError("run.invalid", f"run state changed before it was read: {path}", exit_code=4)
            chunks: list[bytes] = []
            remaining = MAX_RUN_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1_048_576))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        content = b"".join(chunks)
        if (
            len(content) > MAX_RUN_BYTES
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise CtxError("run.invalid", f"run state changed while it was read: {path}", exit_code=4)
        raw = json.loads(content.decode("utf-8"))
    except CtxError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CtxError("run.invalid", f"cannot read run state {path}: {exc}", exit_code=4) from exc
    return _parse_run(raw, path)


def _write_run(run: RunRecord, *, create: bool = False) -> None:
    content = (json.dumps(run.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    _atomic_write(run, content, create=create)


def _project_runs(root: Path) -> tuple[RunRecord, ...]:
    directory = _project_run_dir(root)
    if not directory.exists():
        return ()
    descriptor = _open_project_run_directory(root, create=False)
    os.close(descriptor)
    paths = sorted(directory.glob("*.json"))
    if len(paths) > MAX_RUNS_PER_PROJECT:
        raise CtxError("run.too-many", "project run history exceeds its safety limit", exit_code=4)
    return tuple(_read_run(path) for path in paths)


def _all_runs() -> tuple[RunRecord, ...]:
    root = _runs_root()
    if not root.exists():
        return ()
    descriptor = _open_runs_root(create=False)
    os.close(descriptor)
    try:
        directories = sorted(os.scandir(root), key=lambda value: value.name)
    except OSError as exc:
        raise CtxError("run.read-failed", f"cannot scan run state: {exc}", exit_code=4) from exc
    if len(directories) > MAX_RUNS_PER_PROJECT:
        raise CtxError("run.too-many", "run project directories exceed the safety limit", exit_code=4)
    paths: list[Path] = []
    for entry in directories:
        try:
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                continue
        except OSError:
            continue
        candidate_paths = sorted(Path(entry.path).glob("*.json"))
        if len(candidate_paths) > MAX_RUNS_PER_PROJECT:
            raise CtxError("run.too-many", "project run history exceeds its safety limit", exit_code=4)
        paths.extend(candidate_paths)
        if len(paths) > MAX_GLOBAL_RUNS:
            raise CtxError("run.too-many", "global run history exceeds its safety limit", exit_code=4)
    return tuple(_read_run(path) for path in paths)


def begin_run(
    path: Path,
    *,
    task: str,
    session_id: str | None = None,
    turn_id: str | None = None,
) -> RunRecord:
    if type(task) is not str or len(task) > MAX_TASK_CHARACTERS:
        raise CtxError("run.task-invalid", f"task must be at most {MAX_TASK_CHARACTERS} characters", exit_code=1)
    session_id = _validate_identifier(session_id, "session ID")
    turn_id = _validate_identifier(turn_id, "turn ID")
    ancestry = discover_ancestry(path)
    root = ancestry.project_root.resolve(strict=True)
    for existing in _project_runs(root):
        if session_id is not None and existing.session_id == session_id and turn_id in existing.turn_ids:
            return existing
    starting_status = project_status(root)
    baseline_nodes = {
        node.uri: RunFingerprint(
            node.source_fingerprint,
            node.context_fingerprint,
        )
        for node in starting_status.nodes
    }
    baseline_states = {
        node.uri: node.state if starting_status.lock_valid else "unknown"
        for node in starting_status.nodes
    }
    git_head, dirty_files, limitation = _git_baseline(root)
    if current_run_fingerprints(root) != baseline_nodes:
        raise CtxError(
            "run.project-changed",
            "project changed while the immutable run baseline was being captured; retry",
            exit_code=4,
        )
    directory = _ensure_run_directory(root)
    if session_id is not None and turn_id is not None:
        # User and project hook layers may launch the same matching hook
        # concurrently. A deterministic per-turn ID makes both invocations
        # converge on one immutable baseline instead of creating two runs.
        run_id = hashlib.sha256(
            os.fsencode(str(root))
            + b"\0"
            + session_id.encode("utf-8")
            + b"\0"
            + turn_id.encode("utf-8")
        ).hexdigest()[:32]
        output = directory / f"{run_id}.json"
    else:
        for _attempt in range(8):
            run_id = secrets.token_hex(16)
            output = directory / f"{run_id}.json"
            if not output.exists():
                break
        else:  # pragma: no cover - cryptographic collision defense
            raise CtxError("run.id-failed", "could not allocate a unique run ID", exit_code=4)
    run = RunRecord(
        run_id, root, ancestry.project.id, ancestry.resolved_path, ancestry.current.uri,
        "sha256:" + hashlib.sha256(task.encode("utf-8")).hexdigest(),
        session_id, () if turn_id is None else (turn_id,), baseline_nodes,
        baseline_states,
        git_head, dirty_files, limitation, (), 0, "active", {}, output,
    )
    try:
        _write_run(run, create=True)
        return run
    except CtxError as exc:
        if exc.code != "run.collision":
            raise
        existing = _read_run(output)
        if (
            existing.project_root != root
            or existing.session_id != session_id
            or turn_id not in existing.turn_ids
        ):
            raise
        return existing


def load_run(run_id: str, *, root: Path | None = None) -> RunRecord:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise CtxError("run.id-invalid", "run ID is invalid", exit_code=1)
    if root is not None:
        project_root, _project = find_project_root(root)
        directory = _project_run_dir(project_root)
        if not directory.exists() and not directory.is_symlink():
            raise NotFoundError("run.not-found", f"ctx run does not exist: {run_id}")
        descriptor = _open_project_run_directory(project_root, create=False)
        os.close(descriptor)
        path = _project_run_dir(project_root) / f"{run_id}.json"
        if not path.exists():
            raise NotFoundError("run.not-found", f"ctx run does not exist: {run_id}")
        return _read_run(path)
    runs_root = _runs_root()
    if not runs_root.exists():
        raise NotFoundError("run.not-found", f"ctx run does not exist: {run_id}")
    descriptor = _open_runs_root(create=False)
    os.close(descriptor)
    matches: list[Path] = []
    try:
        entries = sorted(os.scandir(runs_root), key=lambda value: value.name)
    except OSError as exc:
        raise CtxError("run.read-failed", f"cannot scan run state: {exc}", exit_code=4) from exc
    if len(entries) > MAX_RUNS_PER_PROJECT:
        raise CtxError("run.too-many", "run project directories exceed the safety limit", exit_code=4)
    for entry in entries:
        try:
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                continue
        except OSError:
            continue
        candidate = Path(entry.path) / f"{run_id}.json"
        if candidate.exists() or candidate.is_symlink():
            matches.append(candidate)
    if len(matches) != 1:
        raise NotFoundError("run.not-found", f"ctx run does not exist: {run_id}")
    return _read_run(matches[0])


def find_run(path: Path, *, session_id: str, turn_id: str) -> RunRecord | None:
    try:
        root, _project = find_project_root(path)
        candidates = _project_runs(root)
    except CtxError:
        resolved = path.resolve(strict=False)
        candidates = tuple(
            run for run in _all_runs() if is_within(resolved, run.project_root)
        )
    for run in reversed(candidates):
        if run.session_id == session_id and turn_id in run.turn_ids:
            return run
    return None


def _updated(run: RunRecord, **changes: Any) -> RunRecord:
    current = _read_run(run.path)
    if (
        current.baseline_nodes != run.baseline_nodes
        or current.baseline_node_states != run.baseline_node_states
    ):
        raise CtxError("run.baseline-changed", "immutable run baseline changed unexpectedly", exit_code=4)
    updated = replace(current, **changes)
    _write_run(updated)
    return _read_run(updated.path)


def attach_turn(run: RunRecord, *, session_id: str, turn_id: str) -> RunRecord:
    session_id = _validate_identifier(session_id, "session ID") or ""
    turn_id = _validate_identifier(turn_id, "turn ID") or ""
    if run.session_id is not None and run.session_id != session_id:
        raise CtxError("run.session-conflict", "continuation session does not match the run", exit_code=1)
    if run.status != "active" or run.continuation_count != 1:
        raise CtxError(
            "run.continuation-invalid",
            "only the single active Stop continuation may reuse a reconciliation run",
            exit_code=1,
        )
    turns = tuple(dict.fromkeys((*run.turn_ids, turn_id)))
    return _updated(run, session_id=run.session_id or session_id, turn_ids=turns)


def record_acknowledgement(run: RunRecord, uri: str, reason: str) -> RunRecord:
    if not reason.strip() or len(reason) > 500:
        raise CtxError("run.acknowledgement-invalid", "reason must contain 1 to 500 characters", exit_code=1)
    current = current_run_fingerprints(run.project_root)
    affected = {value.uri for value in compare_run(run, current=current)}
    if uri not in affected:
        raise CtxError("run.node-unaffected", f"node is not affected in this run: {uri}", exit_code=1)
    values = {value.uri: value for value in run.acknowledgements}
    values[uri] = RunAcknowledgement(uri, reason.strip(), current.get(uri))
    return _updated(run, acknowledgements=tuple(values[key] for key in sorted(values)))


def compare_run(
    run: RunRecord,
    *,
    current: dict[str, RunFingerprint] | None = None,
) -> tuple[RunNodeChange, ...]:
    current = current_run_fingerprints(run.project_root) if current is None else current
    validation = validate_project(run.project_root, strict=True)
    manifests = {node.uri: node.document.path for node in validation.nodes}
    changes: list[RunNodeChange] = []
    for uri in sorted(set(run.baseline_nodes) | set(current)):
        before = run.baseline_nodes.get(uri)
        after = current.get(uri)
        if before == after:
            continue
        changes.append(
            RunNodeChange(
                uri,
                before is None or after is None or before.source != after.source,
                before is None or after is None or before.context != after.context,
                before is None,
                after is None,
                manifests.get(uri),
            )
        )
    return tuple(changes)


def run_uncovered_changes(
    run: RunRecord,
    *,
    current: dict[str, RunFingerprint] | None = None,
    changes: tuple[RunNodeChange, ...] | None = None,
) -> tuple[RunNodeChange, ...]:
    current = current_run_fingerprints(run.project_root) if current is None else current
    changes = compare_run(run, current=current) if changes is None else changes
    acknowledged = {value.uri: value for value in run.acknowledgements}
    return tuple(
        value
        for value in changes
        if (
            (
                not value.added
                and run.baseline_node_states.get(value.uri, "unknown")
                in {"stale", "context-changed"}
            )
            or (
                (
                    value.requires_acknowledgement
                    or (
                        not value.added
                        and run.baseline_node_states.get(value.uri, "unknown") == "unknown"
                    )
                )
                and (
                    value.uri not in acknowledged
                    or acknowledged[value.uri].fingerprint != current.get(value.uri)
                )
            )
        )
    )


def mark_continuation(run: RunRecord) -> RunRecord:
    return _updated(run, continuation_count=max(run.continuation_count, 1))


def mark_complete(
    run: RunRecord,
    completion_nodes: dict[str, RunFingerprint],
) -> RunRecord:
    return _updated(
        run,
        status="complete",
        completion_nodes=dict(completion_nodes),
    )


def mark_incomplete_allowed(run: RunRecord) -> RunRecord:
    return _updated(run, status="incomplete-allowed")


def completion_is_current(run: RunRecord) -> bool:
    return run.status == "complete" and current_run_fingerprints(run.project_root) == run.completion_nodes
