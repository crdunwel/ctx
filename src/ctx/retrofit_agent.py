from __future__ import annotations

import codecs
import hashlib
import inspect
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable

from .codex_cli import find_codex_executable
from .diagnostics import CtxError, NotFoundError, UnsafePathError
from .freshness import project_status, read_lock_bytes_no_follow
from .paths import is_within, require_safe_context_file
from .retrofit import (
    HARD_EXCLUDED_DIRECTORIES,
    RetrofitInventory,
    _hierarchical_area_paths,
    _is_test_path,
    _open_child_directory_no_follow,
    _open_directory_no_follow,
    inventory_evidence_reasons,
    inventory_repository,
    render_retrofit_prompt,
)
from .registry import ctx_home
from .schema import parse_manifest
from .validation import ValidationResult, validate_project
from .yamlio import MAX_MANIFEST_BYTES, load_yaml


MAX_AGENT_OUTPUT_BYTES = 1_048_576
MAX_AGENT_SECONDS = 1_800
AGENT_HEARTBEAT_SECONDS = 10
MAX_AGENT_ERROR_DETAIL_CHARACTERS = 2_000
MAX_PROPOSED_MANIFESTS = 64
MAX_SUMMARY_CHARACTERS = 4_000
MAX_COVERAGE_AREAS = 1_024
MAX_COVERAGE_EVIDENCE = 64
MAX_CONFLICTS = 64
MAX_CONFLICT_EVIDENCE = 64
MAX_REVIEW_EVIDENCE_REFERENCES = 4_096
MAX_REVIEW_SUMMARY_CHARACTERS = 1_000
MAX_SNAPSHOT_FILES = 50_000
MAX_SNAPSHOT_BYTES = 268_435_456
MAX_INSPECTION_BYTES = 67_108_864
MAX_INSPECTION_TEXT_FILE_BYTES = 2_097_152
MAX_INSPECTION_MEDIA_BYTES = 33_554_432
MAX_INSPECTION_MEDIA_FILE_BYTES = 8_388_608
MAX_INSPECTION_MEDIA_SAMPLES_PER_GROUP = 4
MAX_INSPECTION_MEDIA_RELATIONSHIP_BYTES = 8_388_608
MAX_INSPECTION_MEDIA_RELATIONSHIP_PAIRS = 4
MAX_INSPECTION_RELATIONSHIPS = 1_024
MAX_INSPECTION_CATALOG_GROUPS = 1_024
MAX_INSPECTION_CATALOG_RELATIONSHIPS = 256
MAX_INSPECTION_PREVIEW_BYTES = 8_388_608
MAX_INSPECTION_PREVIEW_FILE_BYTES = 131_072
MAX_INSPECTION_STRUCTURED_FILE_BYTES = 2_097_152
MAX_INSPECTION_REFERENCE_SCAN_BYTES = 8_388_608
MAX_INSPECTION_REFERENCE_DEPTH = 128
MAX_INSPECTION_REFERENCE_NODES = 50_000
MAX_INSPECTION_REFERENCE_PAIR_ATTEMPTS = 50_000
MAX_INSPECTION_REFERENCE_FIELD_VALUES = 4_096
MAX_INSPECTION_CATALOG_BYTES = 2_097_152
MAX_RETROFIT_PLAN_BYTES = 2_097_152
RETROFIT_PLAN_SCHEMA = "ctx-retrofit-plan/v2"

INSPECTION_CATALOG_PATH = ".ctx-retrofit-evidence.json"
INSPECTION_PREVIEW_DIRECTORY = ".ctx-retrofit-previews"
_INSPECTION_RESERVED_PREFIX = ".ctx-retrofit"

_MEDIA_SUFFIXES = {
    ".3gp",
    ".aac",
    ".aiff",
    ".avif",
    ".bmp",
    ".flac",
    ".gif",
    ".heic",
    ".heif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".m4a",
    ".m4v",
    ".mkv",
    ".mov",
    ".mp3",
    ".mp4",
    ".mpeg",
    ".mpg",
    ".ogg",
    ".otf",
    ".png",
    ".tif",
    ".tiff",
    ".ttf",
    ".wav",
    ".webm",
    ".webp",
    ".woff",
    ".woff2",
}

_STRUCTURED_PREVIEW_SUFFIXES = {
    ".csv",
    ".json",
    ".jsonl",
    ".log",
    ".ndjson",
    ".sql",
    ".tsv",
    ".xml",
    ".yaml",
    ".yml",
}

_OPAQUE_SUFFIXES = {
    ".7z",
    ".arrow",
    ".bin",
    ".bz2",
    ".db",
    ".doc",
    ".docx",
    ".feather",
    ".gz",
    ".jar",
    ".model",
    ".onnx",
    ".parquet",
    ".pdf",
    ".pickle",
    ".pkl",
    ".rar",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".tgz",
    ".wasm",
    ".xls",
    ".xlsx",
    ".xz",
    ".zip",
}

_INSTRUCTION_FILE_NAMES = {
    ".cursorrules",
    "agent.md",
    "agents.md",
    "claude.md",
    "gemini.md",
}

_ROOT_MARKER_FILE_NAMES = {
    ".dockerignore",
    ".gitignore",
    ".ignore",
    "build.gradle",
    "build.gradle.kts",
    "cargo.toml",
    "composer.json",
    "deno.json",
    "deno.jsonc",
    "docker-compose.yaml",
    "docker-compose.yml",
    "flake.nix",
    "gemfile",
    "go.mod",
    "justfile",
    "makefile",
    "mix.exs",
    "package.json",
    "package.swift",
    "pom.xml",
    "pyproject.toml",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
}

_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "manifests": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
        },
        "summary": {"type": "string"},
        "coverage": {
            "type": "array",
            "maxItems": MAX_COVERAGE_AREAS,
            "items": {
                "type": "object",
                "properties": {
                    "area": {"type": "string"},
                    "disposition": {
                        "type": "string",
                        "enum": ["node", "ancestor-covered", "excluded", "unresolved"],
                    },
                    "scope": {
                        "anyOf": [
                            {"type": "string"},
                            {"type": "null"},
                        ]
                    },
                    "evidence": {
                        "type": "array",
                        "maxItems": MAX_COVERAGE_EVIDENCE,
                        "items": {"type": "string"},
                    },
                    "summary": {"type": "string"},
                },
                "required": [
                    "area",
                    "disposition",
                    "scope",
                    "evidence",
                    "summary",
                ],
                "additionalProperties": False,
            },
        },
        "conflicts": {
            "type": "array",
            "maxItems": MAX_CONFLICTS,
            "items": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "pattern": "^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$",
                    },
                    "status": {
                        "type": "string",
                        "enum": ["resolved", "review-required"],
                    },
                    "evidence": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_CONFLICT_EVIDENCE,
                        "items": {"type": "string"},
                    },
                    "summary": {"type": "string"},
                },
                "required": ["id", "status", "evidence", "summary"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["manifests", "summary", "coverage", "conflicts"],
    "additionalProperties": False,
}


@dataclass(frozen=True, slots=True)
class ProposedManifest:
    relative_path: str
    destination: Path
    content: str
    node_parts: tuple[str, ...]
    node_identity: tuple[int, int]
    context_identity: tuple[int, int] | None


@dataclass(frozen=True, slots=True)
class CoverageDisposition:
    area: str
    disposition: str
    scope: str | None
    evidence: tuple[str, ...]
    summary: str


@dataclass(frozen=True, slots=True)
class RetrofitConflict:
    id: str
    status: str
    evidence: tuple[str, ...]
    summary: str


@dataclass(frozen=True, slots=True)
class RetrofitRunResult:
    root: Path
    validation: ValidationResult
    created_manifests: tuple[Path, ...]
    proposed_manifests: tuple[Path, ...]
    agent_summary: str
    finalization: object | None = None
    plan_id: str | None = None
    coverage: tuple[CoverageDisposition, ...] = ()
    conflicts: tuple[RetrofitConflict, ...] = ()


@dataclass(frozen=True, slots=True)
class InspectionSnapshot:
    """A bounded agent corpus backed by a full eligible-evidence fingerprint."""

    evidence_fingerprint: str
    verification_fingerprint: str
    copied_bytes: int
    copied_files: int
    preview_bytes: int
    preview_files: int
    elided_files: int
    copied_paths: tuple[str, ...]
    elided_paths: tuple[str, ...]
    preview_paths: tuple[str, ...] = ()
    catalog_path: str = INSPECTION_CATALOG_PATH


@dataclass(frozen=True, slots=True)
class _EvidenceRecord:
    relative_path: str
    size: int
    mode: int
    digest: str
    device: int
    inode: int
    modified_ns: int
    kind: str
    mandatory: bool
    priority: int
    bucket: str


@dataclass(frozen=True, slots=True)
class _InspectionPlan:
    copied: tuple[_EvidenceRecord, ...]
    previews: tuple[_EvidenceRecord, ...]
    duplicate_of: tuple[tuple[str, str], ...]
    relationships: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class _RetrofitPlan:
    plan_id: str
    root: Path
    root_identity: tuple[int, int]
    evidence_fingerprint: str
    manifests: list[dict[str, Any]]
    summary: str
    coverage: tuple[CoverageDisposition, ...]
    conflicts: tuple[RetrofitConflict, ...]


@dataclass(frozen=True, slots=True)
class _CreatedManifest:
    path: Path
    node_fd: int
    context_fd: int
    device: int
    inode: int
    digest: str
    mode: int
    size: int
    modified_ns: int
    context_directory_created: bool


def _review_inventory_areas(inventory: RetrofitInventory) -> tuple[str, ...]:
    """Return the complete bounded source-area vocabulary for semantic review."""

    areas: set[str] = set()
    for relative in inventory.eligible_files:
        directories = PurePosixPath(relative).parts[:-1]
        if not directories:
            areas.add(".")
        else:
            areas.add(directories[0])
            if len(directories) >= 2 and not directories[0].casefold().endswith(
                (".xcodeproj", ".xcworkspace")
            ):
                areas.add(PurePosixPath(*directories[:2]).as_posix())
        if len(areas) > MAX_COVERAGE_AREAS:
            raise CtxError(
                "retrofit.coverage-too-broad",
                "bounded semantic coverage exceeds the automated area limit; "
                "use `ctx retrofit prompt` for a manually scoped review",
                exit_code=4,
            )
    return tuple(sorted(areas))


def _automated_prompt(
    inventory: RetrofitInventory,
    snapshot_root: Path,
    snapshot: InspectionSnapshot,
) -> str:
    snapshot_inventory = replace(inventory, root=snapshot_root)
    return (
        render_retrofit_prompt(snapshot_inventory)
        + f"""

## Automated read-only handoff

This invocation is the guarded `ctx retrofit` adapter. The working directory is
a temporary filtered snapshot, not the live repository. The repository sandbox
is deliberately read-only. Inspect only this current snapshot; do not search
parent, sibling, home, temporary, or other filesystem locations. Do not attempt
to create, edit, register, reconcile, or commit anything, and do not ask for
broader access. Propose only the complete contents of missing
`.ctx/context.yaml` files.
The ctx parent process will reject unsafe destinations, publish new manifests
with no-clobber semantics, run strict validation, and roll back unchanged files
it created if validation fails.
The empty `.ctx-retrofit-root` file is an adapter boundary marker, not project
evidence and not a destination.

## Bounded inspection corpus

The parent process fingerprinted every eligible project file, but this temporary
workspace intentionally contains a bounded inspection selection:
{snapshot.copied_files} complete project files ({snapshot.copied_bytes} bytes),
{snapshot.preview_files} generated structured-data previews
({snapshot.preview_bytes} bytes), and {snapshot.elided_files} project paths
without complete source content, including previews, catalog-only entries, and
duplicates. This selection is deterministic and distributed across project
areas; absence from the workspace does not mean a live project path is absent.

Read `{INSPECTION_CATALOG_PATH}` for normalized path, size, type, digest, and
representation metadata. Entries marked `catalog-only`, `duplicate`, or
`preview` were not available as complete source content. Files under
`{INSPECTION_PREVIEW_DIRECTORY}/`, `{INSPECTION_CATALOG_PATH}`, and every
`.ctx-retrofit*` path are generated adapter data. Never cite them as artifacts,
tracking paths, project files, or evidence. Do not infer the contents of an
uninspected file. Prefer complete source, schemas, producers, consumers,
validators, and repository documentation when proposing durable meaning.
Catalog relationships heuristically derived from bounded eligible JSON identify
candidate paired source/output media paths; `complete_pair_available` means both
were selected for end-to-end inspection, not that the relationship or
transformation was independently verified.

Your final response must match the supplied JSON schema. `manifests` contains
zero or more objects with a normalized project-relative `path` ending exactly
in `.ctx/context.yaml` and the complete UTF-8 YAML `content` with a final
newline. Never return an existing/protected manifest, a source-file edit, a
lock file, or any other path. An empty list is correct when existing context is
already sufficient. `summary` briefly explains the proposed semantic
boundaries and any evidence limitation; do not include source or secret text.

`coverage` is a transient semantic-review record and is never written into a
context manifest. Return exactly one disposition for every bounded eligible
source area in this JSON list (and no other area):
{json.dumps(list(_review_inventory_areas(inventory)), ensure_ascii=True)}
Use `node` when that area has its own proposed or existing manifest,
`ancestor-covered` when an ancestor manifest intentionally provides sufficient
local context, `excluded` when inspected evidence shows the structural area is
not a semantic boundary, or `unresolved` when the nearest useful context scope
cannot yet be decided safely. `scope` is the normalized proposed/existing
`.ctx/context.yaml` path for `node` and `ancestor-covered`; it is null for
`excluded` and `unresolved`. Parent and child inventory areas may overlap, so
the summary must explain an ancestor or exclusion judgment rather than merely
repeat the disposition. Cite at least one normalized project-relative evidence
path from under each area. Do not use generated catalog or preview paths as
evidence. An `unresolved` area deliberately prevents automatic publication or
finalization while remaining visible in a saved dry-run plan.

`conflicts` is also transient. Record each materially inconsistent contract,
document, implementation, test, or context claim once. Use status `resolved`
only when the inspected evidence supports the stated resolution; otherwise use
`review-required`. Every conflict must cite at least one bounded project
evidence path. A `review-required` conflict deliberately prevents automatic
publication or finalization, while remaining visible in a saved dry-run plan.

For this automated handoff, these read-only output rules replace the file-write,
registration, reconciliation, and final-report steps above.
"""
    )


def _temporary_parent(project_root: Path) -> Path:
    candidates = (Path("/private/tmp"), Path("/tmp")) if os.name != "nt" else ()
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_dir() and not is_within(resolved, project_root):
            return resolved
    if os.name == "nt":  # pragma: no cover - exercised on Windows CI
        for variable in ("TEMP", "TMP"):
            raw = os.environ.get(variable)
            if not raw:
                continue
            try:
                resolved = Path(raw).resolve(strict=True)
            except OSError:
                continue
            if resolved.is_dir() and not is_within(resolved, project_root):
                return resolved
    raise CtxError(
        "retrofit.temp-unavailable",
        "cannot find a temporary directory outside the retrofit target",
        exit_code=4,
    )


def _root_identity(root: Path) -> tuple[int, int]:
    try:
        metadata = root.stat()
    except OSError as exc:
        raise CtxError(
            "retrofit.root-changed",
            f"cannot verify retrofit target identity: {exc}",
            exit_code=4,
        ) from exc
    return metadata.st_dev, metadata.st_ino


def _emit_agent_progress(
    progress: Callable[[str], None] | None,
    message: str,
) -> None:
    if progress is not None:
        progress(message)


def _stop_agent_process(process: subprocess.Popen[str]) -> None:
    """Best-effort child cleanup for timeout and interruption paths."""

    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait()
    except OSError:
        pass


def _agent_error_detail(stream: Any) -> str:
    """Return one bounded diagnostic line without replaying Codex's transcript."""

    try:
        stream.flush()
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(max(0, size - 65_536), os.SEEK_SET)
        raw = stream.read()
    except (OSError, ValueError):
        return ""
    if not isinstance(raw, bytes):
        return ""
    markers = ("error", "invalid_", "bad request", "status 4", "status 5")
    for raw_line in reversed(raw.decode("utf-8", errors="replace").splitlines()):
        line = " ".join(raw_line.split())
        if line and any(marker in line.casefold() for marker in markers):
            return line[-MAX_AGENT_ERROR_DETAIL_CHARACTERS:]
    return ""


def _wait_for_agent(
    process: subprocess.Popen[str],
    *,
    progress: Callable[[str], None] | None,
) -> int:
    started = time.monotonic()
    while True:
        elapsed = time.monotonic() - started
        remaining = MAX_AGENT_SECONDS - elapsed
        if remaining <= 0:
            _stop_agent_process(process)
            raise CtxError(
                "retrofit.agent-timeout",
                f"Codex did not finish within {MAX_AGENT_SECONDS} seconds; no "
                "proposed manifests were applied",
                exit_code=4,
            )
        try:
            return process.wait(
                timeout=min(float(AGENT_HEARTBEAT_SECONDS), remaining)
            )
        except subprocess.TimeoutExpired:
            elapsed_seconds = max(1, int(time.monotonic() - started))
            _emit_agent_progress(
                progress,
                "Codex semantic review still running "
                f"({elapsed_seconds}s elapsed; Ctrl-C to stop)",
            )
        except KeyboardInterrupt:
            _stop_agent_process(process)
            _emit_agent_progress(progress, "Codex semantic review interrupted; cleaning up")
            raise


def _run_codex(
    inventory: RetrofitInventory,
    work_directory: Path,
    snapshot_root: Path,
    snapshot: InspectionSnapshot,
    *,
    progress: Callable[[str], None] | None = None,
) -> Path:
    resolved_codex = find_codex_executable()
    if resolved_codex is None:
        raise CtxError(
            "retrofit.agent-not-found",
            "cannot find Codex via CTX_CODEX, PATH, or the macOS ChatGPT app; "
            "install the Codex CLI or use `ctx retrofit prompt` with another agent",
            exit_code=4,
        )
    executable = str(resolved_codex.path)

    schema_path = work_directory / "output-schema.json"
    result_path = work_directory / "agent-result.json"
    sqlite_home = work_directory / "codex-state"
    sqlite_home.mkdir(mode=0o700)
    schema_path.write_text(
        json.dumps(_OUTPUT_SCHEMA, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    command = [
        executable,
        "exec",
        "-C",
        str(snapshot_root),
        "--skip-git-repo-check",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "-c",
        'approval_policy="never"',
        "-c",
        f"sqlite_home={json.dumps(str(sqlite_home))}",
        "-c",
        'default_permissions="ctx-retrofit"',
        "-c",
        'permissions.ctx-retrofit.description="Filtered read-only ctx retrofit"',
        "-c",
        'permissions.ctx-retrofit.filesystem={ ":minimal" = "read", '
        '":workspace_roots" = { "." = "read" } }',
        "-c",
        "permissions.ctx-retrofit.network.enabled=false",
        "-c",
        'project_root_markers=[".ctx-retrofit-root"]',
        "-c",
        'shell_environment_policy.inherit="core"',
        "-c",
        "shell_environment_policy.ignore_default_excludes=false",
        "-c",
        'web_search="disabled"',
        "-c",
        "agents.enabled=false",
        "--disable",
        "hooks",
        "--color",
        "never",
        "--output-schema",
        str(schema_path),
        "--output-last-message",
        str(result_path),
        "-",
    ]

    environment = os.environ.copy()
    python_bin = str(Path(sys.executable).resolve().parent)
    inherited_path = environment.get("PATH", "")
    environment["PATH"] = (
        python_bin if not inherited_path else os.pathsep.join((python_bin, inherited_path))
    )
    prompt = _automated_prompt(inventory, snapshot_root, snapshot)
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as prompt_stream, tempfile.TemporaryFile(
        mode="w+b"
    ) as error_stream:
        prompt_stream.write(prompt)
        prompt_stream.seek(0)
        try:
            process = subprocess.Popen(
                command,
                cwd=snapshot_root,
                env=environment,
                stdin=prompt_stream,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=error_stream,
            )
        except OSError as exc:
            raise CtxError(
                "retrofit.agent-failed",
                f"could not start the Codex agent: {exc}",
                exit_code=4,
            ) from exc

        returncode = _wait_for_agent(process, progress=progress)
        detail = _agent_error_detail(error_stream)
    if returncode != 0:
        detail_suffix = f"; Codex detail: {detail}" if detail else ""
        raise CtxError(
            "retrofit.agent-failed",
            f"Codex exited with status {returncode}; no proposed manifests were applied"
            f"{detail_suffix}",
            exit_code=4,
        )
    if not result_path.is_file() or result_path.is_symlink():
        raise CtxError(
            "retrofit.agent-output-invalid",
            "Codex completed without returning the required manifest proposal",
            exit_code=4,
        )
    return result_path


def _eligible_snapshot_paths(inventory: RetrofitInventory) -> tuple[str, ...]:
    evidence_reasons = inventory_evidence_reasons(inventory)
    if evidence_reasons:
        reasons = ", ".join(evidence_reasons) or "inventory safety bound"
        raise CtxError(
            "retrofit.snapshot-incomplete",
            "automated retrofit requires a complete eligible-file inventory "
            f"({reasons}); use `ctx retrofit prompt` for a manually scoped run",
            exit_code=4,
        )
    paths = tuple(
        sorted(set(inventory.eligible_files) | set(inventory.all_context_manifests))
    )
    if len(paths) > MAX_SNAPSHOT_FILES:
        raise CtxError(
            "retrofit.snapshot-failed",
            f"eligible project evidence contains {len(paths):,} files, exceeding "
            f"the guarded whole-snapshot limit of {MAX_SNAPSHOT_FILES:,}; use "
            "`ctx retrofit prompt` for a manually scoped run",
            exit_code=4,
        )
    for raw_path in paths:
        parts = raw_path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise CtxError(
                "retrofit.snapshot-failed",
                f"inventory returned an unsafe eligible path: {raw_path}",
                exit_code=4,
            )
        if any(part.casefold().startswith(_INSPECTION_RESERVED_PREFIX) for part in parts):
            raise CtxError(
                "retrofit.snapshot-failed",
                f"project evidence uses reserved adapter path {raw_path}; rename it "
                "or use `ctx retrofit prompt` for a manually scoped run",
                exit_code=4,
            )
    return paths


def _open_eligible_file(root_fd: int, raw_path: str) -> int:
    parts = raw_path.split("/")
    parent_fd = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            child_fd = _open_child_directory_no_follow(parent_fd, component)
            os.close(parent_fd)
            parent_fd = child_fd
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        return os.open(parts[-1], flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _is_instruction_inspection_path(relative: str) -> bool:
    pure = PurePosixPath(relative)
    name = pure.name.casefold()
    if name in _INSTRUCTION_FILE_NAMES:
        return True
    return relative.casefold() == ".github/copilot-instructions.md"


def _is_mandatory_inspection_path(relative: str) -> bool:
    pure = PurePosixPath(relative)
    parts = tuple(part.casefold() for part in pure.parts)
    name = pure.name.casefold()
    if len(parts) >= 2 and parts[-2:] == (".ctx", "context.yaml"):
        return True
    if _is_instruction_inspection_path(relative):
        return True
    if len(parts) != 1:
        return False
    return (
        name in _ROOT_MARKER_FILE_NAMES
        or name == "readme"
        or name.startswith("readme.")
        or name == "contributing"
        or name.startswith("contributing.")
        or name == "development.md"
        or name.endswith(".sln")
        or name.endswith(".xcodeproj")
    )


def _inspection_priority(relative: str, mandatory: bool) -> int:
    if mandatory:
        return 0
    pure = PurePosixPath(relative)
    lowered = relative.casefold()
    name = pure.name.casefold()
    suffix = pure.suffix.casefold()
    if name in _ROOT_MARKER_FILE_NAMES:
        return 1
    if any(
        marker in name
        for marker in ("schema", "contract", "migration", "config", "route", "api")
    ) or suffix in {".proto", ".toml"}:
        return 1
    if name.startswith(("main.", "index.", "app.", "server.", "client.")):
        return 2
    if any(part in {"src", "app", "lib", "server", "client", "api"} for part in pure.parts):
        return 3
    if _is_test_path(pure):
        return 4
    if any(part in {"docs", "doc", "examples", "example"} for part in pure.parts):
        return 5
    if len(pure.parts) <= 2:
        return 3
    if "generated" in lowered:
        return 9
    return 6


def _inspection_bucket(relative: str) -> str:
    pure = PurePosixPath(relative)
    areas = _hierarchical_area_paths(pure)
    return areas[-1] if areas else "."


def _inspection_kind(
    relative: str,
    prefix: bytes,
    size: int,
    mandatory: bool,
    *,
    valid_utf8: bool,
) -> str:
    pure = PurePosixPath(relative)
    suffix = pure.suffix.casefold()
    first = pure.parts[0].casefold() if pure.parts else ""
    if mandatory:
        return "text"
    if first in {"confidential", "private"}:
        return "protected"
    if suffix in _MEDIA_SUFFIXES:
        return "media"
    if suffix in _OPAQUE_SUFFIXES:
        return "opaque"
    if b"\x00" in prefix or not valid_utf8:
        return "opaque"
    if suffix in _STRUCTURED_PREVIEW_SUFFIXES and size > MAX_INSPECTION_STRUCTURED_FILE_BYTES:
        return "structured"
    return "text"


def _read_evidence_record(root_fd: int, raw_path: str) -> _EvidenceRecord:
    descriptor: int | None = None
    try:
        descriptor = _open_eligible_file(root_fd, raw_path)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise CtxError(
                "retrofit.snapshot-failed",
                f"eligible snapshot path is not a regular file: {raw_path}",
                exit_code=4,
            )
        hasher = hashlib.sha256()
        prefix = bytearray()
        total = 0
        suffix = PurePosixPath(raw_path).suffix.casefold()
        validate_utf8 = suffix not in _MEDIA_SUFFIXES | _OPAQUE_SUFFIXES
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        valid_utf8 = True
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            hasher.update(chunk)
            total += len(chunk)
            if len(prefix) < 8_192:
                prefix.extend(chunk[: 8_192 - len(prefix)])
            if validate_utf8 and valid_utf8:
                try:
                    decoder.decode(chunk, final=False)
                except UnicodeDecodeError:
                    valid_utf8 = False
        if validate_utf8 and valid_utf8:
            try:
                decoder.decode(b"", final=True)
            except UnicodeDecodeError:
                valid_utf8 = False
        current = os.fstat(descriptor)
        if (
            total != opened.st_size
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or current.st_size != opened.st_size
            or current.st_mtime_ns != opened.st_mtime_ns
            or stat.S_IMODE(current.st_mode) != stat.S_IMODE(opened.st_mode)
        ):
            raise CtxError(
                "retrofit.snapshot-failed",
                f"eligible file changed while fingerprinting: {raw_path}",
                exit_code=4,
            )
        mandatory = _is_mandatory_inspection_path(raw_path)
        pure = PurePosixPath(raw_path)
        return _EvidenceRecord(
            raw_path,
            total,
            stat.S_IMODE(current.st_mode),
            hasher.hexdigest(),
            current.st_dev,
            current.st_ino,
            current.st_mtime_ns,
            _inspection_kind(
                raw_path,
                bytes(prefix),
                total,
                mandatory,
                valid_utf8=valid_utf8,
            ),
            mandatory,
            _inspection_priority(raw_path, mandatory),
            _inspection_bucket(raw_path),
        )
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "retrofit.snapshot-failed",
            f"cannot safely fingerprint eligible path {raw_path}: {exc}",
            exit_code=4,
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _evidence_records(
    inventory: RetrofitInventory, root_fd: int
) -> tuple[_EvidenceRecord, ...]:
    return tuple(
        _read_evidence_record(root_fd, raw_path)
        for raw_path in _eligible_snapshot_paths(inventory)
    )


def _fingerprint_records(records: tuple[_EvidenceRecord, ...]) -> str:
    evidence = hashlib.sha256()
    for record in records:
        path_bytes = record.relative_path.encode("utf-8")
        evidence.update(len(path_bytes).to_bytes(8, "big"))
        evidence.update(path_bytes)
        evidence.update(record.mode.to_bytes(4, "big"))
        evidence.update(record.size.to_bytes(8, "big"))
        evidence.update(bytes.fromhex(record.digest))
    return f"sha256:{evidence.hexdigest()}"


def _fingerprint_eligible_evidence(
    inventory: RetrofitInventory,
    root_fd: int,
    *,
    exclude_paths: frozenset[str] = frozenset(),
) -> str:
    """Hash every eligible file without materializing a second agent snapshot."""

    records = _evidence_records(inventory, root_fd)
    if exclude_paths:
        records = tuple(
            record
            for record in records
            if record.relative_path not in exclude_paths
        )
    return _fingerprint_records(records)


def _stable_record_key(record: _EvidenceRecord) -> tuple[bytes, str]:
    digest = hashlib.sha256(
        b"ctx-inspection-selection/v1\0"
        + record.relative_path.encode("utf-8", errors="surrogateescape")
    ).digest()
    return digest, record.relative_path


def _fair_order(records: list[_EvidenceRecord]) -> tuple[_EvidenceRecord, ...]:
    """Prioritize within areas, then round-robin across semantic areas."""

    ordered: list[_EvidenceRecord] = []
    pending: dict[str, list[_EvidenceRecord]] = {}
    for record in records:
        pending.setdefault(record.bucket, []).append(record)
    buckets: dict[str, deque[_EvidenceRecord]] = {}
    for bucket, values in pending.items():
        values.sort(key=lambda value: (value.priority, _stable_record_key(value)))
        buckets[bucket] = deque(values)
    active = sorted(buckets)
    while active:
        next_active: list[str] = []
        for bucket in active:
            values = buckets[bucket]
            ordered.append(values.popleft())
            if values:
                next_active.append(bucket)
        active = next_active
    return tuple(ordered)


def _promote_required_records(
    records: tuple[_EvidenceRecord, ...], required_paths: frozenset[str]
) -> tuple[_EvidenceRecord, ...]:
    if not required_paths:
        return records
    available = {record.relative_path for record in records}
    missing = sorted(required_paths - available)
    if missing:
        raise CtxError(
            "retrofit.snapshot-incomplete",
            f"required reconciliation evidence is not eligible for guarded "
            f"inspection: {missing[0]}; use `ctx reconcile prompt` for manual review",
            exit_code=4,
        )
    return tuple(
        replace(record, mandatory=True, priority=0)
        if record.relative_path in required_paths and not record.mandatory
        else record
        for record in records
    )


def _select_inspection_records(
    records: tuple[_EvidenceRecord, ...],
    inspection_paths: frozenset[str] | None,
    required_paths: frozenset[str],
    mandatory_paths: frozenset[str] | None,
) -> tuple[_EvidenceRecord, ...]:
    if inspection_paths is None:
        return records
    if any(type(path) is not str for path in inspection_paths):
        raise CtxError(
            "retrofit.snapshot-incomplete",
            "scoped inspection paths must be normalized project-relative strings",
            exit_code=4,
        )
    available = {record.relative_path for record in records}
    missing = sorted(inspection_paths - available)
    if missing:
        raise CtxError(
            "retrofit.snapshot-incomplete",
            f"scoped inspection evidence is not eligible for guarded inspection: "
            f"{missing[0]}",
            exit_code=4,
        )
    selected = inspection_paths | required_paths
    return tuple(
        record
        for record in records
        if record.relative_path in selected
        or (
            record.mandatory
            and (
                mandatory_paths is None
                or record.relative_path in mandatory_paths
            )
        )
    )


def _plan_inspection(
    records: tuple[_EvidenceRecord, ...],
    *,
    manual_command: str,
) -> _InspectionPlan:
    budget = min(MAX_INSPECTION_BYTES, MAX_SNAPSHOT_BYTES)
    mandatory = [record for record in records if record.mandatory]
    mandatory_bytes = sum(record.size for record in mandatory)
    if mandatory_bytes > budget:
        largest = max(mandatory, key=lambda value: value.size)
        raise CtxError(
            "retrofit.snapshot-failed",
            f"mandatory inspection evidence uses {mandatory_bytes:,} bytes, exceeding "
            f"the bounded corpus budget of {budget:,}; largest contributor is "
            f"{largest.relative_path} ({largest.size:,} bytes). Use "
            f"`{manual_command}` for a manually scoped run",
            exit_code=4,
        )

    oversized_text = [
        record
        for record in records
        if record.kind == "text" and not record.mandatory and record.size > budget
    ]
    if oversized_text:
        largest = max(oversized_text, key=lambda value: value.size)
        raise CtxError(
            "retrofit.snapshot-failed",
            f"inspectable source file {largest.relative_path} is {largest.size:,} "
            f"bytes, exceeding the bounded corpus budget of {budget:,}; use "
            f"`{manual_command}` for a manually scoped run",
            exit_code=4,
        )

    copied = list(sorted(mandatory, key=lambda value: value.relative_path))
    selected_paths = {record.relative_path for record in copied}
    duplicate_of: dict[str, str] = {}
    selected_digest: dict[tuple[str, int], str] = {
        (record.digest, record.mode): record.relative_path for record in copied
    }
    remaining = budget - mandatory_bytes

    text_candidates = [
        record
        for record in records
        if record.kind == "text"
        and record.size <= MAX_INSPECTION_TEXT_FILE_BYTES
        and record.relative_path not in selected_paths
    ]
    for record in _fair_order(text_candidates):
        representative = selected_digest.get((record.digest, record.mode))
        if representative is not None:
            duplicate_of[record.relative_path] = representative
            continue
        if record.size <= remaining:
            copied.append(record)
            selected_paths.add(record.relative_path)
            selected_digest[(record.digest, record.mode)] = record.relative_path
            remaining -= record.size

    previews: list[_EvidenceRecord] = []
    preview_remaining = min(MAX_INSPECTION_PREVIEW_BYTES, remaining)
    preview_candidates = [
        record
        for record in records
        if record.kind == "structured"
        or (
            record.kind == "text"
            and record.size > MAX_INSPECTION_TEXT_FILE_BYTES
            and record.relative_path not in selected_paths
        )
    ]
    for record in _fair_order(preview_candidates):
        representative = selected_digest.get((record.digest, record.mode))
        if representative is not None:
            duplicate_of[record.relative_path] = representative
            continue
        estimated = _preview_reserved_bytes(record)
        if estimated <= preview_remaining:
            previews.append(record)
            selected_digest[(record.digest, record.mode)] = record.relative_path
            preview_remaining -= estimated
            remaining -= estimated

    base_media_budget = max(
        0,
        MAX_INSPECTION_MEDIA_BYTES - MAX_INSPECTION_MEDIA_RELATIONSHIP_BYTES,
    )
    media_remaining = min(base_media_budget, remaining)
    media = [record for record in records if record.kind == "media"]
    selected_media_groups: dict[tuple[str, str], int] = {}
    for record in _fair_order(media):
        representative = selected_digest.get((record.digest, record.mode))
        if representative is not None:
            duplicate_of[record.relative_path] = representative
            continue
        group = (record.bucket, PurePosixPath(record.relative_path).suffix.casefold())
        if (
            selected_media_groups.get(group, 0)
            >= MAX_INSPECTION_MEDIA_SAMPLES_PER_GROUP
        ):
            continue
        if (
            record.size > MAX_INSPECTION_MEDIA_FILE_BYTES
            or record.size > media_remaining
        ):
            continue
        copied.append(record)
        selected_paths.add(record.relative_path)
        selected_digest[(record.digest, record.mode)] = record.relative_path
        selected_media_groups[group] = selected_media_groups.get(group, 0) + 1
        media_remaining -= record.size
        remaining -= record.size

    copied.sort(key=lambda value: value.relative_path)
    previews.sort(key=lambda value: value.relative_path)
    return _InspectionPlan(
        tuple(copied),
        tuple(previews),
        tuple(sorted(duplicate_of.items())),
    )


def _read_record_bytes(root_fd: int, record: _EvidenceRecord) -> bytes:
    descriptor: int | None = None
    try:
        descriptor = _open_eligible_file(root_fd, record.relative_path)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (record.device, record.inode)
            or opened.st_size != record.size
            or opened.st_mtime_ns != record.modified_ns
            or stat.S_IMODE(opened.st_mode) != record.mode
        ):
            raise CtxError(
                "retrofit.snapshot-failed",
                f"eligible file changed before relationship scan: {record.relative_path}",
                exit_code=4,
            )
        chunks: list[bytes] = []
        remaining = record.size
        hasher = hashlib.sha256()
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            hasher.update(chunk)
            remaining -= len(chunk)
        current = os.fstat(descriptor)
        data = b"".join(chunks)
        if (
            len(data) != record.size
            or hasher.hexdigest() != record.digest
            or (current.st_dev, current.st_ino) != (record.device, record.inode)
            or current.st_size != record.size
            or current.st_mtime_ns != record.modified_ns
            or stat.S_IMODE(current.st_mode) != record.mode
        ):
            raise CtxError(
                "retrofit.snapshot-failed",
                f"eligible file changed during relationship scan: {record.relative_path}",
                exit_code=4,
            )
        return data
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "retrofit.snapshot-failed",
            f"cannot safely inspect path references in {record.relative_path}: {exc}",
            exit_code=4,
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _media_aliases(records: tuple[_EvidenceRecord, ...]) -> dict[str, str]:
    aliases: dict[str, str | None] = {}

    def add(alias: str, relative: str) -> None:
        existing = aliases.get(alias)
        aliases[alias] = relative if existing in {None, relative} else ""

    for record in records:
        if record.kind != "media":
            continue
        relative = record.relative_path
        add(relative, relative)
        add(f"/{relative}", relative)
        if relative.startswith("public/"):
            public_path = relative[len("public/") :]
            add(public_path, relative)
            add(f"/{public_path}", relative)
        if relative.startswith("raw-photos/"):
            add(PurePosixPath(relative).name, relative)
    return {key: value for key, value in aliases.items() if value}


def _discover_media_relationships(
    root_fd: int,
    records: tuple[_EvidenceRecord, ...],
    plan: _InspectionPlan,
) -> tuple[tuple[str, str, str], ...]:
    aliases = _media_aliases(records)
    if not aliases:
        return ()
    copied = {record.relative_path for record in plan.copied}
    json_records = [
        record
        for record in records
        if record.relative_path in copied
        and PurePosixPath(record.relative_path).suffix.casefold() == ".json"
        and record.size <= MAX_INSPECTION_STRUCTURED_FILE_BYTES
    ]
    remaining = MAX_INSPECTION_REFERENCE_SCAN_BYTES
    relationships: set[tuple[str, str, str]] = set()
    nodes_seen = 0
    pair_attempts = 0
    source_markers = ("input", "original", "raw", "source")
    output_markers = ("asset", "derived", "image", "output", "photo", "processed")

    def resolved_list(value: object) -> tuple[str, ...]:
        if isinstance(value, str):
            resolved = aliases.get(value)
            return (resolved,) if resolved else ()
        if type(value) is not list:
            return ()
        if len(value) > MAX_INSPECTION_REFERENCE_FIELD_VALUES:
            return ()
        resolved_values: list[str] = []
        for item in value:
            if not isinstance(item, str):
                return ()
            resolved = aliases.get(item)
            if resolved is None:
                return ()
            resolved_values.append(resolved)
        return tuple(resolved_values)

    def visit(value: object, evidence_path: str) -> None:
        nonlocal nodes_seen, pair_attempts
        stack: list[tuple[object, int]] = [(value, 0)]
        while (
            stack
            and nodes_seen < MAX_INSPECTION_REFERENCE_NODES
            and pair_attempts < MAX_INSPECTION_REFERENCE_PAIR_ATTEMPTS
            and len(relationships) < MAX_INSPECTION_RELATIONSHIPS
        ):
            current, depth = stack.pop()
            nodes_seen += 1
            if depth > MAX_INSPECTION_REFERENCE_DEPTH:
                continue
            if type(current) is dict:
                keyed: dict[str, tuple[str, ...]] = {}
                for field_index, (key, child) in enumerate(current.items()):
                    if field_index >= MAX_INSPECTION_REFERENCE_FIELD_VALUES:
                        break
                    keyed[str(key).casefold()] = resolved_list(child)
                sources = [
                    refs
                    for key, refs in keyed.items()
                    if refs and any(marker in key for marker in source_markers)
                ]
                outputs = [
                    refs
                    for key, refs in keyed.items()
                    if refs
                    and not any(marker in key for marker in source_markers)
                    and any(marker in key for marker in output_markers)
                ]
                exhausted = False
                for source_refs in sources:
                    for output_refs in outputs:
                        pair_attempts += 1
                        if pair_attempts > MAX_INSPECTION_REFERENCE_PAIR_ATTEMPTS:
                            exhausted = True
                            break
                        if len(source_refs) != len(output_refs):
                            continue
                        if (
                            pair_attempts + len(source_refs)
                            > MAX_INSPECTION_REFERENCE_PAIR_ATTEMPTS
                        ):
                            exhausted = True
                            break
                        pair_attempts += len(source_refs)
                        for source_path, output_path in zip(
                            source_refs, output_refs, strict=True
                        ):
                            if source_path != output_path:
                                relationships.add(
                                    (evidence_path, source_path, output_path)
                                )
                                if (
                                    len(relationships)
                                    >= MAX_INSPECTION_RELATIONSHIPS
                                ):
                                    return
                    if exhausted:
                        break
                if exhausted:
                    return
                if depth < MAX_INSPECTION_REFERENCE_DEPTH:
                    available = max(
                        0,
                        MAX_INSPECTION_REFERENCE_NODES
                        - nodes_seen
                        - len(stack),
                    )
                    for child in current.values():
                        if not available:
                            break
                        if type(child) in {dict, list}:
                            stack.append((child, depth + 1))
                            available -= 1
            elif type(current) is list and depth < MAX_INSPECTION_REFERENCE_DEPTH:
                available = max(
                    0,
                    MAX_INSPECTION_REFERENCE_NODES - nodes_seen - len(stack),
                )
                for child in current:
                    if not available:
                        break
                    if type(child) in {dict, list}:
                        stack.append((child, depth + 1))
                        available -= 1

    for record in sorted(json_records, key=lambda value: value.relative_path):
        if record.size > remaining:
            continue
        remaining -= record.size
        try:
            value = json.loads(_read_record_bytes(root_fd, record).decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            continue
        visit(value, record.relative_path)
        if (
            not remaining
            or nodes_seen >= MAX_INSPECTION_REFERENCE_NODES
            or pair_attempts >= MAX_INSPECTION_REFERENCE_PAIR_ATTEMPTS
            or len(relationships) >= MAX_INSPECTION_RELATIONSHIPS
        ):
            break
    return tuple(sorted(relationships))


def _complete_relationship_samples(
    records: tuple[_EvidenceRecord, ...],
    plan: _InspectionPlan,
    relationships: tuple[tuple[str, str, str], ...],
) -> _InspectionPlan:
    if not relationships:
        return plan
    by_path = {record.relative_path: record for record in records}
    copied = list(plan.copied)
    selected = {record.relative_path for record in copied}
    duplicate_of = dict(plan.duplicate_of)
    reserved_previews = sum(_preview_reserved_bytes(record) for record in plan.previews)
    remaining = max(
        0,
        min(MAX_INSPECTION_BYTES, MAX_SNAPSHOT_BYTES)
        - sum(record.size for record in copied)
        - reserved_previews,
    )
    media_used = sum(record.size for record in copied if record.kind == "media")
    relationship_remaining = min(
        remaining,
        MAX_INSPECTION_MEDIA_RELATIONSHIP_BYTES,
        max(0, MAX_INSPECTION_MEDIA_BYTES - media_used),
    )
    completed = 0

    def add_pair(left: str, right: str) -> bool:
        nonlocal relationship_remaining, completed
        missing = [path for path in (left, right) if path not in selected]
        additions = [by_path[path] for path in missing if path in by_path]
        if len(additions) != len(missing):
            return False
        needed = sum(record.size for record in additions)
        if any(
            record.kind != "media"
            or record.size > MAX_INSPECTION_MEDIA_FILE_BYTES
            for record in additions
        ) or needed > relationship_remaining:
            return False
        for record in additions:
            copied.append(record)
            selected.add(record.relative_path)
            duplicate_of.pop(record.relative_path, None)
        relationship_remaining -= needed
        completed += 1
        return True

    partially_selected = [
        value
        for value in relationships
        if (value[1] in selected) != (value[2] in selected)
    ]
    for _evidence, left, right in partially_selected:
        if completed >= MAX_INSPECTION_MEDIA_RELATIONSHIP_PAIRS:
            break
        add_pair(left, right)

    if completed < MAX_INSPECTION_MEDIA_RELATIONSHIP_PAIRS:
        unselected = sorted(
            (
                value
                for value in relationships
                if value[1] not in selected and value[2] not in selected
            ),
            key=lambda value: (
                by_path[value[1]].size + by_path[value[2]].size,
                value,
            ),
        )
        for _evidence, left, right in unselected:
            if completed >= MAX_INSPECTION_MEDIA_RELATIONSHIP_PAIRS:
                break
            add_pair(left, right)

    copied.sort(key=lambda value: value.relative_path)
    return _InspectionPlan(
        tuple(copied),
        plan.previews,
        tuple(sorted(duplicate_of.items())),
        relationships,
    )


def _snapshot_parts(relative: str) -> tuple[str, ...]:
    parts = tuple(relative.split("/"))
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise CtxError(
            "retrofit.snapshot-failed",
            f"unsafe generated snapshot path: {relative}",
            exit_code=4,
        )
    return parts


def _open_snapshot_directory(path: Path) -> int | None:
    """Open an adapter-owned directory through its canonical ancestor path."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    if sys.platform == "darwin" and len(absolute.parts) >= 2:
        trusted_aliases = {
            "etc": Path("/private/etc"),
            "tmp": Path("/private/tmp"),
            "var": Path("/private/var"),
        }
        trusted = trusted_aliases.get(absolute.parts[1])
        if trusted is not None:
            absolute = trusted.joinpath(*absolute.parts[2:])
    return _open_directory_no_follow(absolute)


def _open_snapshot_parent(
    snapshot_fd: int, relative: str, *, create: bool
) -> tuple[int, str]:
    parts = _snapshot_parts(relative)
    parent_fd = os.dup(snapshot_fd)
    try:
        for component in parts[:-1]:
            try:
                child_fd = _open_child_directory_no_follow(parent_fd, component)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o700, dir_fd=parent_fd)
                except FileExistsError:
                    pass
                child_fd = _open_child_directory_no_follow(parent_fd, component)
            os.close(parent_fd)
            parent_fd = child_fd
        return parent_fd, parts[-1]
    except Exception:
        os.close(parent_fd)
        raise


def _create_snapshot_file(
    snapshot_fd: int, relative: str, mode: int
) -> int:
    parent_fd: int | None = None
    try:
        parent_fd, name = _open_snapshot_parent(snapshot_fd, relative, create=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(name, flags, mode, dir_fd=parent_fd)
        os.fchmod(descriptor, mode)
        return descriptor
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "retrofit.snapshot-failed",
            f"cannot safely create generated snapshot path {relative}: {exc}",
            exit_code=4,
        ) from exc
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


def _write_snapshot_bytes(
    snapshot_fd: int, relative: str, data: bytes, mode: int = 0o400
) -> None:
    descriptor = _create_snapshot_file(snapshot_fd, relative, mode)
    try:
        _write_all(descriptor, data)
    finally:
        os.close(descriptor)


def _copy_record(
    root_fd: int,
    snapshot_fd: int,
    record: _EvidenceRecord,
) -> None:
    source_fd: int | None = None
    destination_fd: int | None = None
    try:
        source_fd = _open_eligible_file(root_fd, record.relative_path)
        opened = os.fstat(source_fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (record.device, record.inode)
            or opened.st_size != record.size
            or opened.st_mtime_ns != record.modified_ns
            or stat.S_IMODE(opened.st_mode) != record.mode
        ):
            raise CtxError(
                "retrofit.snapshot-failed",
                f"eligible file changed before inspection copy: {record.relative_path}",
                exit_code=4,
            )
        destination_fd = _create_snapshot_file(
            snapshot_fd,
            record.relative_path,
            record.mode,
        )
        hasher = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(source_fd, 65_536)
            if not chunk:
                break
            hasher.update(chunk)
            total += len(chunk)
            _write_all(destination_fd, chunk)
        current = os.fstat(source_fd)
        if (
            total != record.size
            or hasher.hexdigest() != record.digest
            or (current.st_dev, current.st_ino) != (record.device, record.inode)
            or current.st_size != record.size
            or current.st_mtime_ns != record.modified_ns
            or stat.S_IMODE(current.st_mode) != record.mode
        ):
            raise CtxError(
                "retrofit.snapshot-failed",
                f"eligible file changed while copying: {record.relative_path}",
                exit_code=4,
            )
        os.fchmod(destination_fd, record.mode)
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "retrofit.snapshot-failed",
            f"cannot safely copy eligible path {record.relative_path}: {exc}",
            exit_code=4,
        ) from exc
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        if source_fd is not None:
            os.close(source_fd)


def _preview_path(record: _EvidenceRecord) -> str:
    key = hashlib.sha256(record.relative_path.encode("utf-8")).hexdigest()
    return f"{INSPECTION_PREVIEW_DIRECTORY}/{key}.preview.txt"


def _preview_header(record: _EvidenceRecord) -> bytes:
    return (
        "CTX bounded source preview; this generated file is not authoritative "
        "source and must never be cited as a manifest artifact.\n"
        f"source path: {record.relative_path}\n"
        f"source bytes: {record.size}\n"
        "--- first bounded bytes ---\n"
    ).encode("utf-8")


def _preview_reserved_bytes(record: _EvidenceRecord) -> int:
    middle = b"\n--- omitted middle; final bounded bytes ---\n"
    footer = b"\n"
    return (
        len(_preview_header(record))
        + min(record.size, MAX_INSPECTION_PREVIEW_FILE_BYTES)
        + (len(middle) if record.size > MAX_INSPECTION_PREVIEW_FILE_BYTES else 0)
        + len(footer)
    )


def _write_preview(
    root_fd: int,
    snapshot_fd: int,
    record: _EvidenceRecord,
) -> int:
    descriptor: int | None = None
    try:
        descriptor = _open_eligible_file(root_fd, record.relative_path)
        opened = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino) != (record.device, record.inode)
            or opened.st_size != record.size
            or opened.st_mtime_ns != record.modified_ns
            or stat.S_IMODE(opened.st_mode) != record.mode
        ):
            raise CtxError(
                "retrofit.snapshot-failed",
                f"eligible file changed before preview: {record.relative_path}",
                exit_code=4,
            )
        half = (
            MAX_INSPECTION_PREVIEW_FILE_BYTES
            if record.size <= MAX_INSPECTION_PREVIEW_FILE_BYTES
            else max(1, MAX_INSPECTION_PREVIEW_FILE_BYTES // 2)
        )
        head = bytearray()
        tail = bytearray()
        hasher = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            hasher.update(chunk)
            total += len(chunk)
            if len(head) < half:
                head.extend(chunk[: half - len(head)])
            tail.extend(chunk)
            if len(tail) > half:
                del tail[:-half]
        current = os.fstat(descriptor)
        if (
            total != record.size
            or hasher.hexdigest() != record.digest
            or (current.st_dev, current.st_ino) != (record.device, record.inode)
            or current.st_size != record.size
            or current.st_mtime_ns != record.modified_ns
            or stat.S_IMODE(current.st_mode) != record.mode
        ):
            raise CtxError(
                "retrofit.snapshot-failed",
                f"eligible file changed while previewing: {record.relative_path}",
                exit_code=4,
            )
        body = bytes(head).decode("utf-8", errors="ignore")
        if record.size > len(head):
            body += "\n--- omitted middle; final bounded bytes ---\n"
            body += bytes(tail).decode("utf-8", errors="ignore")
        rendered = _preview_header(record) + body.encode("utf-8") + b"\n"
        if len(rendered) > _preview_reserved_bytes(record):
            raise CtxError(
                "retrofit.snapshot-failed",
                f"bounded preview accounting failed for {record.relative_path}",
                exit_code=4,
            )
        _write_snapshot_bytes(
            snapshot_fd,
            _preview_path(record),
            rendered,
        )
        return len(rendered)
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "retrofit.snapshot-failed",
            f"cannot safely preview eligible path {record.relative_path}: {exc}",
            exit_code=4,
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _catalog_bytes(
    records: tuple[_EvidenceRecord, ...],
    plan: _InspectionPlan,
    evidence_fingerprint: str,
) -> bytes:
    copied = {record.relative_path for record in plan.copied}
    previews = {record.relative_path: _preview_path(record) for record in plan.previews}
    duplicates = dict(plan.duplicate_of)
    groups: dict[tuple[str, str], dict[str, object]] = {}
    entries: list[dict[str, object]] = []
    for record in records:
        key = (record.bucket, record.kind)
        group = groups.setdefault(
            key,
            {"area": record.bucket, "kind": record.kind, "files": 0, "bytes": 0},
        )
        group["files"] = int(group["files"]) + 1
        group["bytes"] = int(group["bytes"]) + record.size
        if record.relative_path in copied:
            representation = "copied"
            detail: dict[str, object] = {}
        elif record.relative_path in previews:
            representation = "preview"
            detail = {"preview": previews[record.relative_path]}
        elif record.relative_path in duplicates:
            representation = "duplicate"
            detail = {"duplicate_of": duplicates[record.relative_path]}
        else:
            representation = "catalog-only"
            detail = {"reason": f"bounded-{record.kind}-inspection"}
        entries.append(
            {
                "path": record.relative_path,
                "bytes": record.size,
                "mode": f"{record.mode:04o}",
                "sha256": record.digest,
                "kind": record.kind,
                "representation": representation,
                **detail,
            }
        )
    group_entries = [groups[key] for key in sorted(groups)]
    relationship_entries = [
        {
            "evidence": evidence,
            "paths": [left, right],
            "complete_pair_available": left in copied and right in copied,
        }
        for evidence, left, right in plan.relationships
    ]
    payload: dict[str, object] = {
        "schema": "ctx-inspection-catalog/v1",
        "warning": (
            "Catalog and preview files are generated adapter data, not project "
            "source or valid manifest artifacts. Catalog-only paths were not "
            "available to the agent as source content."
        ),
        "evidence_fingerprint": evidence_fingerprint,
        "source": {
            "files": len(records),
            "bytes": sum(record.size for record in records),
        },
        "inspection": {
            "copied_files": len(plan.copied),
            "copied_bytes": sum(record.size for record in plan.copied),
            "preview_files": len(plan.previews),
            "catalog_only_files": len(records) - len(plan.copied) - len(plan.previews),
        },
        "groups": group_entries[:MAX_INSPECTION_CATALOG_GROUPS],
        "catalog_groups_omitted": max(
            0, len(group_entries) - MAX_INSPECTION_CATALOG_GROUPS
        ),
        "relationships": relationship_entries[
            :MAX_INSPECTION_CATALOG_RELATIONSHIPS
        ],
        "catalog_relationships_omitted": max(
            0,
            len(relationship_entries) - MAX_INSPECTION_CATALOG_RELATIONSHIPS,
        ),
        "files": [],
        "catalog_entries_omitted": len(entries),
    }
    preferred = sorted(
        entries,
        key=lambda value: (
            value["representation"] not in {"copied", "preview"},
            hashlib.sha256(str(value["path"]).encode("utf-8")).digest(),
        ),
    )
    base = (json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    if len(base) > MAX_INSPECTION_CATALOG_BYTES:
        raise CtxError(
            "retrofit.snapshot-failed",
            "bounded inspection catalog summaries exceed their safety limit; use "
            "`ctx retrofit prompt` for a manually scoped run",
            exit_code=4,
        )
    bounded: list[dict[str, object]] = []
    estimated = len(base)
    for entry in preferred:
        encoded_entry = json.dumps(
            entry, ensure_ascii=True, sort_keys=True
        ).encode("utf-8")
        additional = len(encoded_entry) + (2 if bounded else 0)
        if estimated + additional > MAX_INSPECTION_CATALOG_BYTES:
            continue
        bounded.append(entry)
        estimated += additional
    payload["files"] = sorted(bounded, key=lambda value: str(value["path"]))
    payload["catalog_entries_omitted"] = len(entries) - len(bounded)
    rendered = (json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    while len(rendered) > MAX_INSPECTION_CATALOG_BYTES and bounded:
        bounded.pop()
        payload["files"] = sorted(
            bounded, key=lambda value: str(value["path"])
        )
        payload["catalog_entries_omitted"] = len(entries) - len(bounded)
        rendered = (
            json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n"
        ).encode("utf-8")
    if len(rendered) > MAX_INSPECTION_CATALOG_BYTES:
        raise CtxError(
            "retrofit.snapshot-failed",
            "bounded inspection catalog exceeds its safety limit; use `ctx retrofit "
            "prompt` for a manually scoped run",
            exit_code=4,
        )
    return rendered


def _build_filtered_snapshot(
    inventory: RetrofitInventory,
    root_fd: int,
    snapshot_root: Path,
    *,
    inspection_paths: frozenset[str] | None = None,
    mandatory_paths: frozenset[str] | None = None,
    required_paths: frozenset[str] = frozenset(),
    verification_exclude_paths: frozenset[str] = frozenset(),
    manual_command: str = "ctx retrofit prompt",
) -> InspectionSnapshot:
    """Build a bounded corpus while hashing every eligible source byte.

    A scoped selection limits model-visible source while retaining mandatory
    repository instructions, explicit required paths, the complete catalog,
    and the full evidence fingerprint.
    """

    original_records = _evidence_records(inventory, root_fd)
    records = _promote_required_records(original_records, required_paths)
    fingerprint = _fingerprint_records(records)
    verification_fingerprint = _fingerprint_records(
        tuple(
            record
            for record in records
            if record.relative_path not in verification_exclude_paths
        )
    )
    inspection_records = _select_inspection_records(
        records, inspection_paths, required_paths, mandatory_paths
    )
    plan = _plan_inspection(inspection_records, manual_command=manual_command)
    relationships = _discover_media_relationships(
        root_fd, inspection_records, plan
    )
    plan = _complete_relationship_samples(
        inspection_records, plan, relationships
    )
    snapshot_root.mkdir(mode=0o700)
    snapshot_fd = _open_snapshot_directory(snapshot_root)
    if snapshot_fd is None:  # pragma: no cover - guarded callers are POSIX-only
        raise CtxError(
            "retrofit.platform-unsupported",
            "guarded snapshots require no-follow directory descriptors",
            exit_code=4,
        )
    try:
        _write_snapshot_bytes(snapshot_fd, ".ctx-retrofit-root", b"")
        for record in plan.copied:
            _copy_record(root_fd, snapshot_fd, record)
        preview_bytes = 0
        for record in plan.previews:
            preview_bytes += _write_preview(root_fd, snapshot_fd, record)
        catalog = _catalog_bytes(records, plan, fingerprint)
        copied_bytes = sum(record.size for record in plan.copied)
        inspection_bytes = copied_bytes + preview_bytes
        if inspection_bytes > min(MAX_INSPECTION_BYTES, MAX_SNAPSHOT_BYTES):
            raise CtxError(
                "retrofit.snapshot-failed",
                f"planned inspection content uses {inspection_bytes:,} bytes, "
                f"exceeding its {MAX_INSPECTION_BYTES:,}-byte budget; use "
                f"`{manual_command}` for a manually scoped run",
                exit_code=4,
            )
        total_snapshot_bytes = inspection_bytes + len(catalog)
        if total_snapshot_bytes > MAX_SNAPSHOT_BYTES:
            raise CtxError(
                "retrofit.snapshot-failed",
                f"planned whole snapshot uses {total_snapshot_bytes:,} bytes, exceeding "
                f"the absolute {MAX_SNAPSHOT_BYTES:,}-byte limit; use "
                f"`{manual_command}` for a manually scoped run",
                exit_code=4,
            )
        _write_snapshot_bytes(snapshot_fd, INSPECTION_CATALOG_PATH, catalog)
    finally:
        os.close(snapshot_fd)
    copied_paths = tuple(record.relative_path for record in plan.copied)
    preview_paths = tuple(record.relative_path for record in plan.previews)
    copied_set = set(copied_paths)
    elided_paths = tuple(
        record.relative_path
        for record in records
        if record.relative_path not in copied_set
    )
    return InspectionSnapshot(
        evidence_fingerprint=fingerprint,
        verification_fingerprint=verification_fingerprint,
        copied_bytes=copied_bytes,
        copied_files=len(plan.copied),
        preview_bytes=preview_bytes,
        preview_files=len(plan.previews),
        elided_files=len(elided_paths),
        copied_paths=copied_paths,
        elided_paths=elided_paths,
        preview_paths=preview_paths,
    )


def _materialize_validation_placeholders(
    snapshot_root: Path, snapshot: InspectionSnapshot
) -> None:
    """Restore only path existence after agent inspection for strict validation."""

    snapshot_fd = _open_snapshot_directory(snapshot_root)
    if snapshot_fd is None:  # pragma: no cover - guarded callers are POSIX-only
        raise CtxError(
            "retrofit.platform-unsupported",
            "guarded snapshots require no-follow directory descriptors",
            exit_code=4,
        )
    try:
        try:
            metadata = os.stat(
                INSPECTION_CATALOG_PATH,
                dir_fd=snapshot_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as exc:
            raise CtxError(
                "retrofit.snapshot-failed",
                "generated inspection catalog disappeared before validation",
                exit_code=4,
            ) from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise CtxError(
                "retrofit.snapshot-failed",
                "generated inspection catalog changed type before validation",
                exit_code=4,
            )
        os.unlink(INSPECTION_CATALOG_PATH, dir_fd=snapshot_fd)

        try:
            preview_fd = _open_child_directory_no_follow(
                snapshot_fd, INSPECTION_PREVIEW_DIRECTORY
            )
        except FileNotFoundError:
            preview_fd = None
        except OSError as exc:
            raise CtxError(
                "retrofit.snapshot-failed",
                "generated inspection preview directory changed type before validation",
                exit_code=4,
            ) from exc
        if preview_fd is not None:
            try:
                for name in os.listdir(preview_fd):
                    metadata = os.stat(name, dir_fd=preview_fd, follow_symlinks=False)
                    if not stat.S_ISREG(metadata.st_mode):
                        raise CtxError(
                            "retrofit.snapshot-failed",
                            "generated inspection preview changed type before validation",
                            exit_code=4,
                        )
                    os.unlink(name, dir_fd=preview_fd)
            finally:
                os.close(preview_fd)
            os.rmdir(INSPECTION_PREVIEW_DIRECTORY, dir_fd=snapshot_fd)

        for relative in snapshot.elided_paths:
            parent_fd: int | None = None
            try:
                parent_fd, name = _open_snapshot_parent(
                    snapshot_fd, relative, create=True
                )
                try:
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise CtxError(
                        "retrofit.snapshot-failed",
                        f"elided snapshot path appeared before validation: {relative}",
                        exit_code=4,
                    )
            finally:
                if parent_fd is not None:
                    os.close(parent_fd)
            descriptor = _create_snapshot_file(snapshot_fd, relative, 0o400)
            os.close(descriptor)
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "retrofit.snapshot-failed",
            f"cannot safely prepare validation-only snapshot paths: {exc}",
            exit_code=4,
        ) from exc
    finally:
        os.close(snapshot_fd)


def _materialize_validation_files(
    root_fd: int,
    snapshot_root: Path,
    paths: frozenset[str],
) -> None:
    """Copy hidden source only after agent execution for strict validation."""

    if not paths:
        return
    snapshot_fd = _open_snapshot_directory(snapshot_root)
    if snapshot_fd is None:  # pragma: no cover - guarded callers are POSIX-only
        raise CtxError(
            "retrofit.platform-unsupported",
            "guarded snapshots require no-follow directory descriptors",
            exit_code=4,
        )
    try:
        for relative in sorted(paths):
            record = _read_evidence_record(root_fd, relative)
            _copy_record(root_fd, snapshot_fd, record)
    finally:
        os.close(snapshot_fd)


def _review_error(code: str, message: str) -> CtxError:
    return CtxError(code, message, exit_code=1)


def _bounded_review_text(value: object, field: str, *, code: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > MAX_REVIEW_SUMMARY_CHARACTERS
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
    ):
        raise _review_error(
            code,
            f"{field} must be non-empty, trimmed, bounded printable text",
        )
    return value


def _normalized_review_path(value: object, field: str, *, code: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 4_096
        or "\\" in value
        or "\x00" in value
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
    ):
        raise _review_error(code, f"{field} contains an unsafe evidence path")
    pure = PurePosixPath(value)
    windows = PureWindowsPath(value)
    parts = value.split("/")
    if (
        pure.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or pure.as_posix() != value
        or any(part in {"", ".", ".."} for part in parts)
        or any(part.casefold().startswith(_INSPECTION_RESERVED_PREFIX) for part in parts)
    ):
        raise _review_error(code, f"{field} contains an unsafe evidence path")
    return value


def _normalized_review_area(
    value: object,
    *,
    code: str,
    allowed_areas: tuple[str, ...] | None,
) -> str:
    if type(value) is not str or not value or len(value) > 4_096 or "\x00" in value:
        raise _review_error(code, "coverage area is not a bounded inventory label")
    if allowed_areas is not None and value not in set(allowed_areas):
        raise _review_error(code, f"coverage contains unknown area {value!r}")
    return value


def _normalized_review_scope(value: object, *, code: str) -> str | None:
    if value is None:
        return None
    scope = _normalized_review_path(value, "coverage scope", code=code)
    if tuple(scope.split("/")[-2:]) != (".ctx", "context.yaml"):
        raise _review_error(
            code,
            "coverage scope must be a proposed or existing .ctx/context.yaml path",
        )
    return scope


def _scope_area(scope: str) -> str:
    parts = PurePosixPath(scope).parts[:-2]
    return PurePosixPath(*parts).as_posix() if parts else "."


def _evidence_is_under_area(path: str, area: str) -> bool:
    parts = PurePosixPath(path).parts
    if area == ".":
        return len(parts) == 1
    area_parts = PurePosixPath(area).parts
    return len(parts) > len(area_parts) and parts[: len(area_parts)] == area_parts


def _review_evidence(
    value: object,
    *,
    field: str,
    maximum: int,
    code: str,
    allowed_evidence: frozenset[str] | None,
) -> tuple[str, ...]:
    if type(value) is not list or len(value) > maximum:
        raise _review_error(
            code,
            f"{field} must be a bounded list of project-relative evidence paths",
        )
    normalized: list[str] = []
    for path in value:
        if type(path) is not str or not path or len(path) > 4_096 or "\x00" in path:
            raise _review_error(code, f"{field} contains an invalid inventory path")
        if allowed_evidence is not None and path not in allowed_evidence:
            raise _review_error(
                code,
                f"{field} references evidence outside the bounded inventory: {path!r}",
            )
        normalized.append(path)
    normalized_tuple = tuple(normalized)
    if len(set(normalized_tuple)) != len(normalized_tuple):
        raise _review_error(code, f"{field} contains duplicate evidence paths")
    return tuple(sorted(normalized_tuple))


def _parse_review_envelope(
    coverage_value: object,
    conflicts_value: object,
    *,
    code: str,
    allowed_areas: tuple[str, ...] | None = None,
    allowed_evidence: frozenset[str] | None = None,
    inspectable_evidence: frozenset[str] | None = None,
    allowed_scopes: frozenset[str] | None = None,
) -> tuple[tuple[CoverageDisposition, ...], tuple[RetrofitConflict, ...]]:
    if type(coverage_value) is not list or len(coverage_value) > MAX_COVERAGE_AREAS:
        raise _review_error(code, "coverage must be a bounded list of area dispositions")
    coverage: list[CoverageDisposition] = []
    seen_areas: set[str] = set()
    evidence_references = 0
    for item in coverage_value:
        if (
            type(item) is not dict
            or set(item)
            != {"area", "disposition", "scope", "evidence", "summary"}
        ):
            raise _review_error(
                code,
                "each coverage disposition requires exactly area, disposition, "
                "scope, evidence, and summary",
            )
        area = _normalized_review_area(
            item["area"], code=code, allowed_areas=allowed_areas
        )
        if area in seen_areas:
            raise _review_error(code, f"coverage contains duplicate area {area}")
        seen_areas.add(area)
        disposition = item["disposition"]
        if type(disposition) is not str or disposition not in {
            "node",
            "ancestor-covered",
            "excluded",
            "unresolved",
        }:
            raise _review_error(code, f"coverage area {area} has an invalid disposition")
        scope = _normalized_review_scope(item["scope"], code=code)
        if disposition in {"node", "ancestor-covered"}:
            if scope is None:
                raise _review_error(
                    code,
                    f"coverage area {area} requires a governing manifest scope",
                )
            if allowed_scopes is not None and scope not in allowed_scopes:
                raise _review_error(
                    code,
                    f"coverage area {area} references a scope that is neither "
                    f"existing nor proposed: {scope}",
                )
            governing_area = _scope_area(scope)
            if disposition == "node" and governing_area != area:
                raise _review_error(
                    code,
                    f"node coverage for {area} must use a manifest in that area",
                )
            if disposition == "ancestor-covered" and (
                governing_area == area
                or (
                    governing_area != "."
                    and not area.startswith(f"{governing_area}/")
                )
            ):
                raise _review_error(
                    code,
                    f"ancestor coverage for {area} must use an ancestor manifest",
                )
        elif scope is not None:
            raise _review_error(
                code,
                f"coverage area {area} must use null scope for disposition {disposition}",
            )
        evidence = _review_evidence(
            item["evidence"],
            field=f"coverage evidence for {area}",
            maximum=MAX_COVERAGE_EVIDENCE,
            code=code,
            allowed_evidence=allowed_evidence,
        )
        evidence_references += len(evidence)
        if any(not _evidence_is_under_area(path, area) for path in evidence):
            raise _review_error(
                code,
                f"coverage evidence for {area} must map under that inventory area",
            )
        if not evidence:
            raise _review_error(
                code,
                f"coverage area {area} requires representative evidence",
            )
        if (
            disposition != "unresolved"
            and inspectable_evidence is not None
            and not set(evidence).intersection(inspectable_evidence)
        ):
            raise _review_error(
                code,
                f"coverage area {area} must cite at least one inspected path",
            )
        summary = _bounded_review_text(
            item["summary"], f"coverage summary for {area}", code=code
        )
        coverage.append(CoverageDisposition(area, disposition, scope, evidence, summary))
    if allowed_areas is not None:
        if len(allowed_areas) > MAX_COVERAGE_AREAS:
            raise _review_error(
                code,
                "bounded inventory contains too many semantic review areas",
            )
        expected = set(allowed_areas)
        missing = sorted(expected - seen_areas)
        extra = sorted(seen_areas - expected)
        if missing or extra:
            detail = f"missing {missing[0]}" if missing else f"unknown {extra[0]}"
            raise _review_error(
                code,
                "coverage must contain exactly one disposition per bounded "
                f"inventory area ({detail})",
            )

    if type(conflicts_value) is not list or len(conflicts_value) > MAX_CONFLICTS:
        raise _review_error(code, "conflicts must be a bounded list")
    conflicts: list[RetrofitConflict] = []
    seen_conflicts: set[str] = set()
    for item in conflicts_value:
        if (
            type(item) is not dict
            or set(item) != {"id", "status", "evidence", "summary"}
        ):
            raise _review_error(
                code,
                "each conflict requires exactly id, status, evidence, and summary",
            )
        conflict_id = item["id"]
        if type(conflict_id) is not str or re.fullmatch(
            r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?", conflict_id
        ) is None:
            raise _review_error(code, "conflict IDs must be bounded lowercase identities")
        if conflict_id in seen_conflicts:
            raise _review_error(code, f"conflicts contains duplicate ID {conflict_id}")
        seen_conflicts.add(conflict_id)
        status = item["status"]
        if type(status) is not str or status not in {"resolved", "review-required"}:
            raise _review_error(code, f"conflict {conflict_id} has an invalid status")
        evidence = _review_evidence(
            item["evidence"],
            field=f"conflict evidence for {conflict_id}",
            maximum=MAX_CONFLICT_EVIDENCE,
            code=code,
            allowed_evidence=allowed_evidence,
        )
        evidence_references += len(evidence)
        if not evidence:
            raise _review_error(code, f"conflict {conflict_id} requires evidence")
        if inspectable_evidence is not None and not set(evidence).issubset(inspectable_evidence):
            raise _review_error(
                code,
                f"conflict {conflict_id} cites evidence that was not inspected",
            )
        summary = _bounded_review_text(
            item["summary"], f"conflict summary for {conflict_id}", code=code
        )
        conflicts.append(RetrofitConflict(conflict_id, status, evidence, summary))
    if evidence_references > MAX_REVIEW_EVIDENCE_REFERENCES:
        raise _review_error(code, "semantic review contains too many evidence references")
    return (
        tuple(sorted(coverage, key=lambda value: value.area)),
        tuple(sorted(conflicts, key=lambda value: value.id)),
    )


def _read_agent_output(
    path: Path,
    inventory: RetrofitInventory,
    snapshot: InspectionSnapshot,
) -> tuple[
    list[dict[str, Any]],
    str,
    tuple[CoverageDisposition, ...],
    tuple[RetrofitConflict, ...],
]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CtxError(
            "retrofit.agent-output-invalid",
            f"cannot read the Codex manifest proposal: {exc}",
            exit_code=4,
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_AGENT_OUTPUT_BYTES:
            raise CtxError(
                "retrofit.agent-output-invalid",
                "Codex manifest proposal is not a bounded regular file",
                exit_code=1,
            )
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_AGENT_OUTPUT_BYTES:
            chunk = os.read(
                descriptor,
                min(65_536, MAX_AGENT_OUTPUT_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_AGENT_OUTPUT_BYTES:
        raise CtxError(
            "retrofit.agent-output-invalid",
            "Codex manifest proposal exceeds the output safety limit",
            exit_code=1,
        )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CtxError(
            "retrofit.agent-output-invalid",
            f"Codex returned invalid proposal JSON: {exc}",
            exit_code=1,
        ) from exc
    required = {"manifests", "summary", "coverage", "conflicts"}
    if type(value) is not dict or set(value) != required:
        raise CtxError(
            "retrofit.agent-output-invalid",
            "Codex proposal must contain exactly manifests, summary, coverage, and conflicts",
            exit_code=1,
        )
    manifests = value["manifests"]
    summary = value["summary"]
    if type(manifests) is not list or len(manifests) > MAX_PROPOSED_MANIFESTS:
        raise CtxError(
            "retrofit.agent-output-invalid",
            f"Codex may propose at most {MAX_PROPOSED_MANIFESTS} manifests",
            exit_code=1,
        )
    if type(summary) is not str or len(summary) > MAX_SUMMARY_CHARACTERS:
        raise CtxError(
            "retrofit.agent-output-invalid",
            "Codex proposal summary is missing or too large",
            exit_code=1,
        )
    for item in manifests:
        if type(item) is not dict or set(item) != {"path", "content"}:
            raise CtxError(
                "retrofit.agent-output-invalid",
                "each Codex manifest proposal requires exactly path and content",
                exit_code=1,
            )
    allowed_evidence = frozenset(_eligible_snapshot_paths(inventory))
    inspectable_evidence = frozenset(snapshot.copied_paths) | frozenset(
        snapshot.preview_paths
    )
    proposed_scopes = frozenset(
        item["path"]
        for item in manifests
        if type(item.get("path")) is str
        and tuple(item["path"].split("/")[-2:]) == (".ctx", "context.yaml")
    )
    coverage, conflicts = _parse_review_envelope(
        value["coverage"],
        value["conflicts"],
        code="retrofit.agent-output-invalid",
        allowed_areas=_review_inventory_areas(inventory),
        allowed_evidence=allowed_evidence,
        inspectable_evidence=inspectable_evidence,
        allowed_scopes=proposed_scopes | frozenset(inventory.all_context_manifests),
    )
    return manifests, summary, coverage, conflicts


def _canonical_plan_payload(
    root: Path,
    root_identity: tuple[int, int],
    evidence_fingerprint: str,
    proposals: tuple[ProposedManifest, ...],
    summary: str,
    coverage: tuple[CoverageDisposition, ...],
    conflicts: tuple[RetrofitConflict, ...],
) -> dict[str, Any]:
    return {
        "schema": RETROFIT_PLAN_SCHEMA,
        "root": str(root),
        "root_identity": {
            "device": root_identity[0],
            "inode": root_identity[1],
        },
        "evidence_fingerprint": evidence_fingerprint,
        "manifests": [
            {"path": proposal.relative_path, "content": proposal.content}
            for proposal in sorted(proposals, key=lambda value: value.relative_path)
        ],
        "summary": summary,
        "coverage": [
            {
                "area": item.area,
                "disposition": item.disposition,
                "scope": item.scope,
                "evidence": list(item.evidence),
                "summary": item.summary,
            }
            for item in coverage
        ],
        "conflicts": [
            {
                "id": item.id,
                "status": item.status,
                "evidence": list(item.evidence),
                "summary": item.summary,
            }
            for item in conflicts
        ],
    }


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _plan_directory(*, create: bool) -> Path:
    home = ctx_home()
    plans = home / "retrofit-plans"
    try:
        if create:
            home.mkdir(mode=0o700, parents=True, exist_ok=True)
            if home.is_symlink() or not home.is_dir():
                raise UnsafePathError(
                    "retrofit.plan-home-unsafe",
                    f"CTX_HOME is unsafe: {home}",
                )
            plans.mkdir(mode=0o700, exist_ok=True)
        if home.is_symlink() or plans.is_symlink():
            raise UnsafePathError(
                "retrofit.plan-home-unsafe",
                f"retrofit plan storage cannot be a symlink: {plans}",
            )
        if plans.exists() and not plans.is_dir():
            raise UnsafePathError(
                "retrofit.plan-home-unsafe",
                f"retrofit plan storage is not a directory: {plans}",
            )
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "retrofit.plan-write-failed" if create else "retrofit.plan-read-failed",
            f"cannot access retrofit plan storage {plans}: {exc}",
            exit_code=4,
        ) from exc
    return plans


def _save_retrofit_plan(
    root: Path,
    root_identity: tuple[int, int],
    evidence_fingerprint: str,
    proposals: tuple[ProposedManifest, ...],
    summary: str,
    coverage: tuple[CoverageDisposition, ...],
    conflicts: tuple[RetrofitConflict, ...],
) -> str:
    payload = _canonical_plan_payload(
        root,
        root_identity,
        evidence_fingerprint,
        proposals,
        summary,
        coverage,
        conflicts,
    )
    canonical = _canonical_json(payload)
    if len(canonical) > MAX_RETROFIT_PLAN_BYTES:
        raise CtxError(
            "retrofit.plan-too-large",
            "validated retrofit proposal exceeds the saved-plan safety limit",
            exit_code=4,
        )
    plan_id = hashlib.sha256(canonical).hexdigest()
    directory = _plan_directory(create=True)
    target = directory / f"{plan_id}.json"
    content = canonical + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=directory,
        prefix=".retrofit-plan.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, content)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError:
            flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
            existing_fd = os.open(target, flags)
            try:
                existing = b""
                while len(existing) <= MAX_RETROFIT_PLAN_BYTES:
                    chunk = os.read(
                        existing_fd,
                        min(65_536, MAX_RETROFIT_PLAN_BYTES + 1 - len(existing)),
                    )
                    if not chunk:
                        break
                    existing += chunk
            finally:
                os.close(existing_fd)
            if existing != content:
                raise CtxError(
                    "retrofit.plan-conflict",
                    f"saved retrofit plan ID collision: {plan_id}",
                    exit_code=4,
                )
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "retrofit.plan-write-failed",
            f"cannot save validated retrofit plan: {exc}",
            exit_code=4,
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return plan_id


def _load_retrofit_plan(plan_id: str) -> _RetrofitPlan:
    if not re.fullmatch(r"[0-9a-f]{64}", plan_id):
        raise CtxError(
            "retrofit.plan-invalid",
            "retrofit plan ID must be exactly 64 lowercase hexadecimal characters",
            exit_code=1,
        )
    directory = _plan_directory(create=False)
    path = directory / f"{plan_id}.json"
    flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise CtxError(
            "retrofit.plan-not-found",
            f"saved retrofit plan does not exist: {plan_id}",
            exit_code=1,
        ) from exc
    except OSError as exc:
        raise CtxError(
            "retrofit.plan-read-failed",
            f"cannot open saved retrofit plan {plan_id}: {exc}",
            exit_code=4,
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_RETROFIT_PLAN_BYTES + 1:
            raise CtxError(
                "retrofit.plan-invalid",
                "saved retrofit plan is not a bounded regular file",
                exit_code=1,
            )
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_RETROFIT_PLAN_BYTES:
            chunk = os.read(
                descriptor,
                min(65_536, MAX_RETROFIT_PLAN_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if (
        len(raw) > MAX_RETROFIT_PLAN_BYTES
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise CtxError(
            "retrofit.plan-invalid",
            "saved retrofit plan changed while it was being read",
            exit_code=1,
        )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CtxError(
            "retrofit.plan-invalid",
            f"saved retrofit plan is invalid JSON: {exc}",
            exit_code=1,
        ) from exc
    required = {
        "schema",
        "root",
        "root_identity",
        "evidence_fingerprint",
        "manifests",
        "summary",
        "coverage",
        "conflicts",
    }
    if type(value) is not dict or set(value) != required or value.get("schema") != RETROFIT_PLAN_SCHEMA:
        raise CtxError(
            "retrofit.plan-invalid",
            "saved retrofit plan has an unsupported schema",
            exit_code=1,
        )
    root_raw = value["root"]
    identity_raw = value["root_identity"]
    fingerprint = value["evidence_fingerprint"]
    manifests = value["manifests"]
    summary = value["summary"]
    coverage_raw = value["coverage"]
    conflicts_raw = value["conflicts"]
    if (
        type(root_raw) is not str
        or not Path(root_raw).is_absolute()
        or type(identity_raw) is not dict
        or set(identity_raw) != {"device", "inode"}
        or type(identity_raw["device"]) is not int
        or type(identity_raw["inode"]) is not int
        or type(fingerprint) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", fingerprint) is None
        or type(manifests) is not list
        or len(manifests) > MAX_PROPOSED_MANIFESTS
        or type(summary) is not str
        or len(summary) > MAX_SUMMARY_CHARACTERS
        or any(type(item) is not dict or set(item) != {"path", "content"} for item in manifests)
    ):
        raise CtxError(
            "retrofit.plan-invalid",
            "saved retrofit plan contains invalid fields",
            exit_code=1,
        )
    coverage, conflicts = _parse_review_envelope(
        coverage_raw,
        conflicts_raw,
        code="retrofit.plan-invalid",
    )
    canonical = _canonical_json(value)
    if hashlib.sha256(canonical).hexdigest() != plan_id:
        raise CtxError(
            "retrofit.plan-invalid",
            "saved retrofit plan content does not match its plan ID",
            exit_code=1,
        )
    return _RetrofitPlan(
        plan_id,
        Path(root_raw),
        (identity_raw["device"], identity_raw["inode"]),
        fingerprint,
        manifests,
        summary,
        coverage,
        conflicts,
    )


def render_retrofit_plan(plan_id: str) -> str:
    """Render a saved proposal as terminal-safe JSON for human review."""

    plan = _load_retrofit_plan(plan_id)
    payload = {
        "schema": RETROFIT_PLAN_SCHEMA,
        "plan_id": plan.plan_id,
        "root": str(plan.root),
        "evidence_fingerprint": plan.evidence_fingerprint,
        "manifests": plan.manifests,
        "summary": plan.summary,
        "coverage": [
            {
                "area": item.area,
                "disposition": item.disposition,
                "scope": item.scope,
                "evidence": list(item.evidence),
                "summary": item.summary,
            }
            for item in plan.coverage
        ],
        "conflicts": [
            {
                "id": item.id,
                "status": item.status,
                "evidence": list(item.evidence),
                "summary": item.summary,
            }
            for item in plan.conflicts
        ],
        "review_required": any(
            item.status == "review-required" for item in plan.conflicts
        )
        or any(item.disposition == "unresolved" for item in plan.coverage),
    }
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2) + "\n"


def _proposal_destination(
    root: Path, raw_path: str
) -> tuple[Path, tuple[str, ...], tuple[int, int], tuple[int, int] | None]:
    if (
        not raw_path
        or raw_path != raw_path.strip()
        or "\\" in raw_path
        or "\x00" in raw_path
        or any(
            unicodedata.category(character) in {"Cc", "Cf"}
            for character in raw_path
        )
    ):
        raise UnsafePathError("retrofit.proposal-path", "unsafe proposed manifest path")
    parts = raw_path.split("/")
    pure = PurePosixPath(raw_path)
    windows = PureWindowsPath(raw_path)
    if (
        pure.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or pure.as_posix() != raw_path
        or any(part in {"", ".", ".."} for part in parts)
        or tuple(parts[-2:]) != (".ctx", "context.yaml")
        or any(part in {".ctx", ".git"} for part in parts[:-2])
    ):
        raise UnsafePathError(
            "retrofit.proposal-path",
            f"proposed path must be a normalized missing .ctx/context.yaml: {raw_path}",
        )

    current = root
    try:
        metadata = current.lstat()
    except OSError as exc:
        raise UnsafePathError(
            "retrofit.proposal-path",
            f"cannot inspect retrofit root safely: {raw_path} ({exc})",
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise UnsafePathError(
            "retrofit.proposal-path",
            f"retrofit root is not a real directory: {raw_path}",
        )
    for part in parts[:-2]:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise UnsafePathError(
                "retrofit.proposal-path",
                f"proposed node directory does not exist safely: {raw_path} ({exc})",
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise UnsafePathError(
                "retrofit.proposal-path",
                f"proposed node path is not a real directory: {raw_path}",
            )
        try:
            exact_names = {entry.name for entry in os.scandir(current.parent)}
        except OSError as exc:
            raise UnsafePathError(
                "retrofit.proposal-path",
                f"cannot verify proposed node path case: {raw_path} ({exc})",
            ) from exc
        if part not in exact_names:
            raise UnsafePathError(
                "retrofit.proposal-path",
                f"proposed node path does not match filesystem case: {raw_path}",
            )
        if part.casefold() in HARD_EXCLUDED_DIRECTORIES:
            raise UnsafePathError(
                "retrofit.proposal-path",
                f"proposed node is inside an excluded repository area: {raw_path}",
            )
    node_identity = (metadata.st_dev, metadata.st_ino)
    destination = root.joinpath(*parts)
    context_directory = destination.parent
    context_identity: tuple[int, int] | None = None
    if context_directory.exists() or context_directory.is_symlink():
        try:
            metadata = context_directory.lstat()
        except OSError as exc:
            raise UnsafePathError(
                "retrofit.proposal-path",
                f"cannot inspect proposed context directory safely: {raw_path} ({exc})",
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise UnsafePathError(
                "retrofit.proposal-path",
                f"proposed context directory is not a real directory: {raw_path}",
            )
        context_identity = (metadata.st_dev, metadata.st_ino)
    if destination.exists() or destination.is_symlink():
        raise CtxError(
            "retrofit.protected-manifest",
            f"Codex proposed replacing a protected manifest: {destination}",
            exit_code=1,
        )
    require_safe_context_file(destination)
    return destination, tuple(parts[:-2]), node_identity, context_identity


def _manifest_references_inspection_adapter(manifest: object) -> bool:
    artifacts = getattr(manifest, "artifacts", ())
    tracking = getattr(manifest, "tracking", None)
    values = [getattr(value, "path", "") for value in artifacts]
    if tracking is not None:
        values.extend(getattr(tracking, "include", ()))
        values.extend(getattr(tracking, "exclude", ()))
    return any(
        part.casefold().startswith(_INSPECTION_RESERVED_PREFIX)
        for value in values
        for part in str(value).replace("\\", "/").split("/")
    )


def _prepare_proposals(
    root: Path, raw_items: list[dict[str, Any]], work_directory: Path
) -> tuple[ProposedManifest, ...]:
    proposals: list[ProposedManifest] = []
    destinations: set[Path] = set()
    total_bytes = 0
    proposed_root = False

    for index, raw in enumerate(raw_items):
        raw_path = raw["path"]
        content = raw["content"]
        if type(raw_path) is not str or type(content) is not str:
            raise CtxError(
                "retrofit.agent-output-invalid",
                "proposed manifest path and content must be strings",
                exit_code=1,
            )
        (
            destination,
            node_parts,
            node_identity,
            context_identity,
        ) = _proposal_destination(root, raw_path)
        if destination in destinations:
            raise CtxError(
                "retrofit.agent-output-invalid",
                f"Codex proposed the same manifest more than once: {raw_path}",
                exit_code=1,
            )
        destinations.add(destination)
        encoded = content.encode("utf-8")
        total_bytes += len(encoded)
        if (
            not content
            or not content.endswith("\n")
            or "\r" in content
            or len(encoded) > MAX_MANIFEST_BYTES
            or total_bytes > MAX_AGENT_OUTPUT_BYTES
        ):
            raise CtxError(
                "retrofit.agent-output-invalid",
                f"proposed manifest content is missing, noncanonical, or too large: {raw_path}",
                exit_code=1,
            )

        temporary = work_directory / f"manifest-{index}.yaml"
        temporary.write_text(content, encoding="utf-8", newline="\n")
        raw_text, raw_data = load_yaml(temporary)
        manifest, diagnostics = parse_manifest(raw_data, destination, raw_text=raw_text)
        failures = [
            diagnostic
            for diagnostic in diagnostics
            if diagnostic.severity == "error" or diagnostic.fails_strict
        ]
        if manifest is None or failures:
            detail = failures[0].message if failures else "manifest is invalid"
            raise CtxError(
                "retrofit.agent-output-invalid",
                f"proposed manifest is not strict-valid at {raw_path}: {detail}",
                exit_code=1,
            )
        if _manifest_references_inspection_adapter(manifest):
            raise CtxError(
                "retrofit.agent-output-invalid",
                f"proposed manifest references generated inspection adapter data: {raw_path}",
                exit_code=1,
            )
        is_root = raw_path == ".ctx/context.yaml"
        proposed_root = proposed_root or is_root
        if is_root and (manifest.project is None or manifest.node.id != "root"):
            raise CtxError(
                "retrofit.agent-output-invalid",
                "the proposed project-root manifest must define project and node.id root",
                exit_code=1,
            )
        if not is_root and (manifest.project is not None or manifest.node.id == "root"):
            raise CtxError(
                "retrofit.agent-output-invalid",
                f"proposed nested manifest has root-only identity fields: {raw_path}",
                exit_code=1,
            )
        proposals.append(
            ProposedManifest(
                raw_path,
                destination,
                content,
                node_parts,
                node_identity,
                context_identity,
            )
        )

    if not (root / ".ctx" / "context.yaml").is_file() and not proposed_root:
        raise CtxError(
            "retrofit.incomplete",
            "Codex did not propose the missing project-root context manifest",
            exit_code=1,
        )
    return tuple(sorted(proposals, key=lambda value: (value.relative_path.count("/"), value.relative_path)))


def _open_proposed_node(root_fd: int, proposal: ProposedManifest) -> int:
    descriptor = os.dup(root_fd)
    try:
        for component in proposal.node_parts:
            child = _open_child_directory_no_follow(descriptor, component)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) != proposal.node_identity:
            raise CtxError(
                "retrofit.node-changed",
                f"proposed node directory changed during retrofit: {proposal.relative_path}",
                exit_code=4,
            )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:  # pragma: no cover - defensive OS boundary
            raise OSError("short write while publishing context manifest")
        view = view[written:]


def _publish(
    root_fd: int, proposals: tuple[ProposedManifest, ...]
) -> tuple[_CreatedManifest, ...]:
    created: list[_CreatedManifest] = []
    try:
        for proposal in proposals:
            node_fd = _open_proposed_node(root_fd, proposal)
            context_fd: int | None = None
            context_directory_created = False
            temporary_name: str | None = None
            try:
                if proposal.context_identity is None:
                    try:
                        os.stat(".ctx", dir_fd=node_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        os.mkdir(".ctx", mode=0o755, dir_fd=node_fd)
                        context_directory_created = True
                    else:
                        raise CtxError(
                            "retrofit.context-changed",
                            f"context directory appeared during retrofit: {proposal.relative_path}",
                            exit_code=4,
                        )
                context_fd = _open_child_directory_no_follow(node_fd, ".ctx")
                context_metadata = os.fstat(context_fd)
                if (
                    proposal.context_identity is not None
                    and (context_metadata.st_dev, context_metadata.st_ino)
                    != proposal.context_identity
                ):
                    raise CtxError(
                        "retrofit.context-changed",
                        f"context directory changed during retrofit: {proposal.relative_path}",
                        exit_code=4,
                    )

                try:
                    os.stat("context.yaml", dir_fd=context_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise CtxError(
                        "retrofit.protected-manifest",
                        f"manifest appeared during retrofit and was not replaced: {proposal.destination}",
                        exit_code=1,
                    )

                encoded = proposal.content.encode("utf-8")
                temporary_name = (
                    f".context.yaml.{os.getpid()}.{secrets.token_hex(8)}.tmp"
                )
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                temporary_fd = os.open(
                    temporary_name,
                    flags,
                    0o644,
                    dir_fd=context_fd,
                )
                try:
                    _write_all(temporary_fd, encoded)
                    os.fsync(temporary_fd)
                    metadata = os.fstat(temporary_fd)
                    os.link(
                        temporary_name,
                        "context.yaml",
                        src_dir_fd=context_fd,
                        dst_dir_fd=context_fd,
                        follow_symlinks=False,
                    )
                finally:
                    os.close(temporary_fd)

                record = _CreatedManifest(
                    proposal.destination,
                    node_fd,
                    context_fd,
                    metadata.st_dev,
                    metadata.st_ino,
                    hashlib.sha256(encoded).hexdigest(),
                    stat.S_IMODE(metadata.st_mode),
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    context_directory_created,
                )
                created.append(record)
                node_fd = -1
                context_fd = None
                os.unlink(temporary_name, dir_fd=record.context_fd)
                temporary_name = None
                os.fsync(record.context_fd)
            finally:
                if temporary_name is not None:
                    cleanup_fd = (
                        context_fd
                        if context_fd is not None
                        else (created[-1].context_fd if created else None)
                    )
                    if cleanup_fd is not None:
                        try:
                            os.unlink(temporary_name, dir_fd=cleanup_fd)
                        except OSError:
                            pass
                if context_fd is not None:
                    os.close(context_fd)
                if node_fd >= 0:
                    if context_directory_created:
                        try:
                            os.rmdir(".ctx", dir_fd=node_fd)
                        except OSError:
                            pass
                    os.close(node_fd)
    except Exception:
        _rollback(tuple(created))
        raise
    return tuple(created)


def _rollback(created: tuple[_CreatedManifest, ...]) -> None:
    failures: list[Path] = []
    for record in reversed(created):
        context_fd_open = True
        try:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open("context.yaml", flags, dir_fd=record.context_fd)
            try:
                metadata = os.fstat(descriptor)
                chunks: list[bytes] = []
                total = 0
                while total <= MAX_MANIFEST_BYTES:
                    chunk = os.read(descriptor, min(65_536, MAX_MANIFEST_BYTES + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                digest = hashlib.sha256(b"".join(chunks)).hexdigest()
            finally:
                os.close(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino) != (record.device, record.inode)
                or digest != record.digest
                or stat.S_IMODE(metadata.st_mode) != record.mode
                or metadata.st_size != record.size
                or metadata.st_mtime_ns != record.modified_ns
            ):
                failures.append(record.path)
                continue
            current = os.stat(
                "context.yaml", dir_fd=record.context_fd, follow_symlinks=False
            )
            if (current.st_dev, current.st_ino) != (record.device, record.inode):
                failures.append(record.path)
                continue
            os.unlink("context.yaml", dir_fd=record.context_fd)
            os.fsync(record.context_fd)
            if record.context_directory_created:
                os.close(record.context_fd)
                context_fd_open = False
                os.rmdir(".ctx", dir_fd=record.node_fd)
        except OSError:
            failures.append(record.path)
        finally:
            if context_fd_open:
                os.close(record.context_fd)
            os.close(record.node_fd)
    if failures:
        raise CtxError(
            "retrofit.rollback-failed",
            "strict validation failed, and a concurrently changed manifest could "
            f"not be removed safely: {failures[0]}",
            exit_code=4,
        )


def _release(created: tuple[_CreatedManifest, ...]) -> None:
    for record in created:
        os.close(record.context_fd)
        os.close(record.node_fd)


def _verify_created_locations(
    root_fd: int,
    proposals: tuple[ProposedManifest, ...],
    created: tuple[_CreatedManifest, ...],
) -> None:
    if len(proposals) != len(created):  # pragma: no cover - internal invariant
        raise AssertionError("published manifest count differs from proposal count")
    for proposal, record in zip(proposals, created, strict=True):
        node_fd = _open_proposed_node(root_fd, proposal)
        try:
            context_fd = _open_child_directory_no_follow(node_fd, ".ctx")
            try:
                expected_context = os.fstat(record.context_fd)
                current_context = os.fstat(context_fd)
                flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                manifest_fd = os.open("context.yaml", flags, dir_fd=context_fd)
                try:
                    before = os.fstat(manifest_fd)
                    chunks: list[bytes] = []
                    total = 0
                    while total <= MAX_MANIFEST_BYTES:
                        chunk = os.read(
                            manifest_fd,
                            min(65_536, MAX_MANIFEST_BYTES + 1 - total),
                        )
                        if not chunk:
                            break
                        chunks.append(chunk)
                        total += len(chunk)
                    after = os.fstat(manifest_fd)
                finally:
                    os.close(manifest_fd)
                digest = hashlib.sha256(b"".join(chunks)).hexdigest()
                if (
                    (current_context.st_dev, current_context.st_ino)
                    != (expected_context.st_dev, expected_context.st_ino)
                    or not stat.S_ISREG(before.st_mode)
                    or (before.st_dev, before.st_ino)
                    != (record.device, record.inode)
                    or (after.st_dev, after.st_ino)
                    != (record.device, record.inode)
                    or stat.S_IMODE(before.st_mode) != record.mode
                    or stat.S_IMODE(after.st_mode) != record.mode
                    or before.st_size != record.size
                    or after.st_size != record.size
                    or before.st_mtime_ns != record.modified_ns
                    or after.st_mtime_ns != record.modified_ns
                    or digest != record.digest
                ):
                    raise CtxError(
                        "retrofit.destination-changed",
                        "published manifest bytes or destination changed "
                        f"concurrently: {record.path}",
                        exit_code=4,
                    )
            finally:
                os.close(context_fd)
        except OSError as exc:
            raise CtxError(
                "retrofit.destination-changed",
                f"cannot verify published manifest destination {record.path}: {exc}",
                exit_code=4,
            ) from exc
        finally:
            os.close(node_fd)


def _validate_snapshot_proposals(
    snapshot_root: Path, proposals: tuple[ProposedManifest, ...]
) -> ValidationResult:
    snapshot_fd = _open_snapshot_directory(snapshot_root)
    if snapshot_fd is None:  # pragma: no cover - guarded callers are POSIX-only
        raise CtxError(
            "retrofit.platform-unsupported",
            "guarded snapshots require no-follow directory descriptors",
            exit_code=4,
        )
    try:
        for proposal in proposals:
            parent_fd: int | None = None
            descriptor: int | None = None
            try:
                parent_fd, name = _open_snapshot_parent(
                    snapshot_fd,
                    proposal.relative_path,
                    create=True,
                )
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    descriptor = os.open(name, flags, 0o644, dir_fd=parent_fd)
                except FileExistsError as exc:
                    raise CtxError(
                        "retrofit.protected-manifest",
                        "dry-run proposal would replace a protected manifest: "
                        f"{proposal.relative_path}",
                        exit_code=1,
                    ) from exc
                _write_all(descriptor, proposal.content.encode("utf-8"))
                os.fchmod(descriptor, 0o644)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if parent_fd is not None:
                    os.close(parent_fd)
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "retrofit.snapshot-failed",
            f"cannot safely materialize a validation proposal: {exc}",
            exit_code=4,
        ) from exc
    finally:
        os.close(snapshot_fd)
    return validate_project(snapshot_root, strict=True)


def _fresh_lock_baseline(root: Path) -> bytes | None:
    """Capture an exact pre-publication lock only from a fresh existing graph."""

    try:
        status = project_status(root)
    except NotFoundError:
        return None
    if not status.fresh:
        return None
    path = status.lock_path
    try:
        content = read_lock_bytes_no_follow(path)
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError(
            "retrofit.lock-changed",
            f"cannot capture the reviewed freshness lock: {exc}",
            exit_code=4,
        ) from exc
    try:
        verified_fresh = project_status(root).fresh
        current_content = read_lock_bytes_no_follow(path)
    except (CtxError, OSError) as exc:
        raise CtxError(
            "retrofit.lock-changed",
            f"cannot verify the reviewed freshness lock: {exc}",
            exit_code=4,
        ) from exc
    if (
        not verified_fresh
        or current_content != content
    ):
        raise CtxError(
            "retrofit.lock-changed",
            "the freshness lock changed while the reviewed baseline was captured",
            exit_code=4,
        )
    return content


def _apply_prepared_proposals(
    root: Path,
    original_identity: tuple[int, int],
    root_fd: int,
    proposals: tuple[ProposedManifest, ...],
    summary: str,
    finalize: Callable[..., object] | None,
    expected_evidence_fingerprint: str,
    *,
    plan_id: str | None = None,
    coverage: tuple[CoverageDisposition, ...] = (),
    conflicts: tuple[RetrofitConflict, ...] = (),
) -> RetrofitRunResult:
    replace_fresh_lock = _fresh_lock_baseline(root)

    def require_unchanged(
        *,
        message: str,
        exclude_paths: frozenset[str] = frozenset(),
    ) -> None:
        if _root_identity(root) != original_identity:
            raise CtxError(
                "retrofit.root-changed",
                "retrofit target identity changed during guarded publication",
                exit_code=4,
            )
        _require_evidence_fingerprint(
            root,
            root_fd,
            expected_evidence_fingerprint,
            code="retrofit.source-changed",
            message=message,
            exclude_paths=exclude_paths,
        )
        if _root_identity(root) != original_identity:
            raise CtxError(
                "retrofit.root-changed",
                "retrofit target identity changed during guarded publication",
                exit_code=4,
            )

    require_unchanged(
        message=(
            "eligible project evidence changed immediately before manifest "
            "publication; no proposal was applied"
        )
    )
    created = _publish(root_fd, proposals)
    try:
        if _root_identity(root) != original_identity:
            raise CtxError(
                "retrofit.root-changed",
                "retrofit target changed during manifest publication",
                exit_code=4,
        )
        _verify_created_locations(root_fd, proposals, created)
        validation = validate_project(root, strict=True)
        if _root_identity(root) != original_identity:
            raise CtxError(
                "retrofit.root-changed",
                "retrofit target changed during strict validation",
                exit_code=4,
            )
        _verify_created_locations(root_fd, proposals, created)
        require_unchanged(
            message=(
                "eligible project evidence changed during manifest validation; "
                "new manifests were rolled back"
            ),
            exclude_paths=frozenset(
                proposal.relative_path for proposal in proposals
            ),
        )
    except Exception:
        _rollback(created)
        raise
    if not validation.valid:
        _rollback(created)
        finalization = None
    else:
        excluded_proposals = frozenset(
            proposal.relative_path for proposal in proposals
        )

        def verify_unchanged() -> None:
            require_unchanged(
                message=(
                    "eligible project evidence changed during retrofit "
                    "finalization; lifecycle writes and new manifests were rolled back"
                ),
                exclude_paths=excluded_proposals,
            )
            _verify_created_locations(root_fd, proposals, created)

        try:
            if finalize is None:
                finalization = None
            else:
                try:
                    parameters = inspect.signature(finalize).parameters.values()
                except (TypeError, ValueError):
                    parameters = ()
                accepts_guard = any(
                    parameter.name == "verify_unchanged"
                    or parameter.kind == inspect.Parameter.VAR_KEYWORD
                    for parameter in parameters
                )
                accepts_lock_baseline = any(
                    parameter.name == "replace_fresh_lock"
                    or parameter.kind == inspect.Parameter.VAR_KEYWORD
                    for parameter in parameters
                )
                if accepts_guard:
                    keyword_arguments: dict[str, Any] = {
                        "verify_unchanged": verify_unchanged,
                    }
                    if accepts_lock_baseline:
                        keyword_arguments["replace_fresh_lock"] = replace_fresh_lock
                    finalization = finalize(root, **keyword_arguments)
                else:
                    verify_unchanged()
                    finalization = finalize(root)
                    verify_unchanged()
        except Exception:
            _rollback(created)
            raise
        _release(created)
    return RetrofitRunResult(
        root,
        validation,
        tuple(record.path for record in created) if validation.valid else (),
        tuple(proposal.destination for proposal in proposals),
        summary,
        finalization,
        plan_id,
        coverage,
        conflicts,
    )


def _verified_current_snapshot(
    root: Path,
    root_fd: int,
    *,
    exclude_paths: frozenset[str] = frozenset(),
) -> tuple[RetrofitInventory, str]:
    try:
        inventory = inventory_repository(root)
    except PermissionError as exc:
        raise CtxError(
            "retrofit.read-failed",
            f"cannot inventory retrofit target: {exc}",
            exit_code=4,
        ) from exc
    return inventory, _fingerprint_eligible_evidence(
        inventory,
        root_fd,
        exclude_paths=exclude_paths,
    )


def _require_evidence_fingerprint(
    root: Path,
    root_fd: int,
    expected: str,
    *,
    code: str,
    message: str,
    exclude_paths: frozenset[str] = frozenset(),
) -> None:
    _inventory, current = _verified_current_snapshot(
        root,
        root_fd,
        exclude_paths=exclude_paths,
    )
    if current != expected:
        raise CtxError(code, message, exit_code=4)


def _require_resolved_review(
    coverage: tuple[CoverageDisposition, ...],
    conflicts: tuple[RetrofitConflict, ...],
    *,
    plan_id: str | None = None,
) -> None:
    unresolved_areas = tuple(
        item for item in coverage if item.disposition == "unresolved"
    )
    unresolved_conflicts = tuple(
        conflict for conflict in conflicts if conflict.status == "review-required"
    )
    if not unresolved_areas and not unresolved_conflicts:
        return
    blockers = [f"area:{item.area}" for item in unresolved_areas]
    blockers.extend(f"conflict:{item.id}" for item in unresolved_conflicts)
    identities = ", ".join(blockers[:5])
    if len(blockers) > 5:
        identities += f", and {len(blockers) - 5} more"
    review = (
        f"; inspect with `ctx retrofit --show-plan {plan_id}`"
        if plan_id is not None
        else "; rerun with `ctx retrofit --dry-run` to save the review envelope"
    )
    raise CtxError(
        "retrofit.review-required",
        f"automatic retrofit publication is blocked by unresolved semantic review: "
        f"{identities}{review}",
        exit_code=1,
    )


def _review_display_summary(
    summary: str,
    coverage: tuple[CoverageDisposition, ...],
    conflicts: tuple[RetrofitConflict, ...],
) -> str:
    incomplete = tuple(
        item for item in coverage if item.disposition == "unresolved"
    )
    unresolved = tuple(
        item for item in conflicts if item.status == "review-required"
    )
    notes: list[str] = []
    if coverage:
        dispositions = ", ".join(
            f"{item.area}={item.disposition}" for item in coverage[:8]
        )
        if len(coverage) > 8:
            dispositions += f", and {len(coverage) - 8} more"
        notes.append(f"coverage dispositions {dispositions}")
    if incomplete:
        names = ", ".join(
            item.area for item in incomplete[:8]
        )
        if len(incomplete) > 8:
            names += f", and {len(incomplete) - 8} more"
        notes.append(f"unresolved coverage {names}")
    if conflicts:
        statuses = ", ".join(
            f"{item.id}={item.status}" for item in conflicts[:8]
        )
        if len(conflicts) > 8:
            statuses += f", and {len(conflicts) - 8} more"
        notes.append(f"conflict dispositions {statuses}")
    if unresolved:
        names = ", ".join(item.id for item in unresolved[:8])
        if len(unresolved) > 8:
            names += f", and {len(unresolved) - 8} more"
        notes.append(f"review-required conflicts {names}")
    if not notes:
        return summary
    review = "Semantic review: " + "; ".join(notes) + "."
    return f"{summary.rstrip()} {review}".strip()


def apply_retrofit_plan(
    plan_id: str,
    *,
    path: Path | None = None,
    finalize: Callable[..., object] | None = None,
) -> RetrofitRunResult:
    """Apply the exact strict-valid proposal saved by a prior dry run."""

    plan = _load_retrofit_plan(plan_id)
    _require_resolved_review(
        plan.coverage, plan.conflicts, plan_id=plan.plan_id
    )
    selected_path = plan.root if path is None else path
    try:
        inventory = inventory_repository(selected_path)
    except PermissionError as exc:
        raise CtxError(
            "retrofit.read-failed",
            f"cannot inventory retrofit target: {exc}",
            exit_code=4,
        ) from exc
    if inventory.root != plan.root:
        raise CtxError(
            "retrofit.plan-root-mismatch",
            f"saved plan targets {plan.root}, not {inventory.root}",
            exit_code=1,
        )
    if _root_identity(inventory.root) != plan.root_identity:
        raise CtxError(
            "retrofit.plan-stale",
            "retrofit target identity changed after the dry run; run `ctx retrofit --dry-run` again",
            exit_code=1,
        )
    temporary_parent = _temporary_parent(inventory.root)
    root_fd = _open_directory_no_follow(inventory.root)
    if root_fd is None:
        raise CtxError(
            "retrofit.platform-unsupported",
            "guarded automated retrofit requires no-follow directory descriptors; "
            "use `ctx retrofit prompt` on this platform",
            exit_code=4,
        )
    try:
        anchored_root = os.fstat(root_fd)
        if (anchored_root.st_dev, anchored_root.st_ino) != plan.root_identity:
            raise CtxError(
                "retrofit.plan-stale",
                "retrofit target changed after the dry run; run `ctx retrofit --dry-run` again",
                exit_code=1,
            )
        with tempfile.TemporaryDirectory(
            prefix="ctx-retrofit-apply-", dir=temporary_parent
        ) as raw_work:
            work_directory = Path(raw_work)
            snapshot_root = work_directory / "project"
            inspection = _build_filtered_snapshot(inventory, root_fd, snapshot_root)
            if inspection.evidence_fingerprint != plan.evidence_fingerprint:
                raise CtxError(
                    "retrofit.plan-stale",
                    "eligible project evidence changed after the dry run; run `ctx retrofit --dry-run` again",
                    exit_code=1,
                )
            proposals = _prepare_proposals(
                inventory.root,
                plan.manifests,
                work_directory,
            )
            _materialize_validation_placeholders(snapshot_root, inspection)
            validation = _validate_snapshot_proposals(snapshot_root, proposals)
            if not validation.valid:
                return RetrofitRunResult(
                    inventory.root,
                    validation,
                    (),
                    tuple(proposal.destination for proposal in proposals),
                    plan.summary,
                    None,
                    plan.plan_id,
                    plan.coverage,
                    plan.conflicts,
                )
            if _root_identity(inventory.root) != plan.root_identity:
                raise CtxError(
                    "retrofit.plan-stale",
                    "retrofit target changed while the saved plan was checked",
                    exit_code=1,
                )
            return _apply_prepared_proposals(
                inventory.root,
                plan.root_identity,
                root_fd,
                proposals,
                plan.summary,
                finalize,
                plan.evidence_fingerprint,
                plan_id=plan.plan_id,
                coverage=plan.coverage,
                conflicts=plan.conflicts,
            )
    finally:
        os.close(root_fd)


def run_agent_retrofit(
    path: Path,
    *,
    dry_run: bool = False,
    finalize: Callable[..., object] | None = None,
    codex_executable: str = "codex",
    progress: Callable[[str], None] | None = None,
) -> RetrofitRunResult:
    """Inspect read-only with Codex, then publish only strict-valid new manifests."""

    _emit_agent_progress(progress, f"inventorying project at {path}")
    try:
        inventory = inventory_repository(path)
    except PermissionError as exc:
        raise CtxError(
            "retrofit.read-failed",
            f"cannot inventory retrofit target: {exc}",
            exit_code=4,
        ) from exc
    original_identity = _root_identity(inventory.root)
    temporary_parent = _temporary_parent(inventory.root)
    root_fd = _open_directory_no_follow(inventory.root)
    if root_fd is None:
        raise CtxError(
            "retrofit.platform-unsupported",
            "guarded automated retrofit requires no-follow directory descriptors; "
            "use `ctx retrofit prompt` on this platform",
            exit_code=4,
        )
    try:
        anchored_root = os.fstat(root_fd)
        if (anchored_root.st_dev, anchored_root.st_ino) != original_identity:
            raise CtxError(
                "retrofit.root-changed",
                "retrofit target changed before Codex inspection started",
                exit_code=4,
            )
        with tempfile.TemporaryDirectory(
            prefix="ctx-retrofit-", dir=temporary_parent
        ) as raw_work:
            work_directory = Path(raw_work)
            snapshot_root = work_directory / "project"
            inspection = _build_filtered_snapshot(
                inventory, root_fd, snapshot_root
            )
            inspected_count = len(inspection.copied_paths) + len(
                inspection.preview_paths
            )
            _emit_agent_progress(
                progress,
                f"prepared bounded read-only snapshot ({inspected_count} inspected "
                f"of {len(inventory.eligible_files)} eligible files)",
            )
            evidence_fingerprint = inspection.evidence_fingerprint
            if codex_executable != "codex":
                raise CtxError(
                    "retrofit.agent-unsupported",
                    f"no guarded adapter is installed for agent {codex_executable!r}",
                    exit_code=1,
                )
            _emit_agent_progress(
                progress,
                "starting Codex semantic review (this may take several minutes)",
            )
            if progress is None:
                result_path = _run_codex(
                    inventory,
                    work_directory,
                    snapshot_root,
                    inspection,
                )
            else:
                result_path = _run_codex(
                    inventory,
                    work_directory,
                    snapshot_root,
                    inspection,
                    progress=progress,
                )
            _emit_agent_progress(
                progress,
                "Codex semantic review finished; validating the proposal",
            )
            raw_items, summary, coverage, conflicts = _read_agent_output(
                result_path, inventory, inspection
            )
            if _root_identity(inventory.root) != original_identity:
                raise CtxError(
                    "retrofit.root-changed",
                    "retrofit target changed identity while Codex was inspecting it",
                    exit_code=4,
                )
            _current_inventory, current_fingerprint = _verified_current_snapshot(
                inventory.root,
                root_fd,
            )
            if current_fingerprint != evidence_fingerprint:
                raise CtxError(
                    "retrofit.source-changed",
                    "eligible project evidence changed while Codex was inspecting it; rerun retrofit",
                    exit_code=4,
                )
            proposals = _prepare_proposals(inventory.root, raw_items, work_directory)
            if dry_run:
                _materialize_validation_placeholders(snapshot_root, inspection)
                validation = _validate_snapshot_proposals(snapshot_root, proposals)
                plan_id = None
                if validation.valid:
                    _require_evidence_fingerprint(
                        inventory.root,
                        root_fd,
                        evidence_fingerprint,
                        code="retrofit.source-changed",
                        message=(
                            "eligible project evidence changed while the dry-run "
                            "proposal was validated; no reusable plan was saved"
                        ),
                    )
                    plan_id = _save_retrofit_plan(
                        inventory.root,
                        original_identity,
                        evidence_fingerprint,
                        proposals,
                        summary,
                        coverage,
                        conflicts,
                    )
                return RetrofitRunResult(
                    inventory.root,
                    validation,
                    (),
                    tuple(proposal.destination for proposal in proposals),
                    _review_display_summary(summary, coverage, conflicts),
                    None,
                    plan_id,
                    coverage,
                    conflicts,
                )
            _require_resolved_review(coverage, conflicts)
            return _apply_prepared_proposals(
                inventory.root,
                original_identity,
                root_fd,
                proposals,
                summary,
                finalize,
                evidence_fingerprint,
                coverage=coverage,
                conflicts=conflicts,
            )
    finally:
        os.close(root_fd)
