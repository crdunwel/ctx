from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .diagnostics import CtxError, Diagnostic, UnsafePathError
from .discovery import assign_node_uris, find_project_root, scan_project_documents
from .models import LoadedNode, Manifest, ManifestDocument, Project
from .paths import (
    has_exact_case,
    is_secret_path,
    lexical_project_path,
    normalize_alias,
    require_safe_tracking_path,
    resolved_project_path,
)
from .uri import ContextUri, item_uri, parse_ctx_uri


GENERIC_ALIASES = {"api", "app", "core", "main", "project", "repo", "service", "site", "web"}
LOCK_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_LOCK_BYTES = 4_194_304


@dataclass(frozen=True, slots=True)
class ValidationResult:
    input_path: Path
    project_root: Path
    project: Project
    nodes: tuple[LoadedNode, ...]
    diagnostics: tuple[Diagnostic, ...]
    strict: bool = False

    @property
    def errors(self) -> tuple[Diagnostic, ...]:
        return tuple(value for value in self.diagnostics if value.severity == "error")

    @property
    def warnings(self) -> tuple[Diagnostic, ...]:
        return tuple(value for value in self.diagnostics if value.severity == "warning")

    @property
    def strict_failures(self) -> tuple[Diagnostic, ...]:
        return tuple(
            value
            for value in self.diagnostics
            if value.severity == "warning" and value.fails_strict
        )

    @property
    def valid(self) -> bool:
        return not self.errors and (not self.strict or not self.strict_failures)

    @property
    def unsafe(self) -> bool:
        unsafe_codes = (
            "path.",
            "artifact.secret",
            "tracking.secret",
            "manifest.symlink",
            "manifest.nested-lock",
            "lock.symlink",
        )
        return any(
            value.severity == "error" and value.code.startswith(unsafe_codes)
            for value in self.diagnostics
        )


def _error(
    diagnostics: list[Diagnostic],
    code: str,
    message: str,
    document: ManifestDocument,
    field: str | None = None,
    path: Path | None = None,
) -> None:
    diagnostics.append(Diagnostic("error", code, message, document.path, field, path))


def _warning(
    diagnostics: list[Diagnostic],
    code: str,
    message: str,
    document: ManifestDocument,
    field: str | None = None,
    *,
    fails_strict: bool,
) -> None:
    diagnostics.append(
        Diagnostic(
            "warning",
            code,
            message,
            document.path,
            field,
            fails_strict=fails_strict,
        )
    )


def _validate_root_rules(
    root: Path,
    project: Project,
    documents: tuple[ManifestDocument, ...],
    diagnostics: list[Diagnostic],
) -> None:
    for document in documents:
        manifest = document.manifest
        if manifest is None:
            continue
        is_root = document.node_dir.resolve(strict=True) == root
        if is_root:
            if manifest.project is None:
                _error(
                    diagnostics,
                    "manifest.root-project-missing",
                    "root manifest must define project identity",
                    document,
                    "project",
                )
            if manifest.node.id != "root":
                _error(
                    diagnostics,
                    "manifest.root-id",
                    "root manifest node ID must be 'root'",
                    document,
                    "node.id",
                )
        else:
            if manifest.project is not None:
                _error(
                    diagnostics,
                    "manifest.nested-project",
                    "nested manifests must inherit and cannot redefine project identity",
                    document,
                    "project",
                )
            if manifest.node.id == "root":
                _error(
                    diagnostics,
                    "manifest.nested-root-id",
                    "nested manifest node ID cannot be 'root'",
                    document,
                    "node.id",
                )
            nested_lock = document.path.parent / "lock.json"
            if nested_lock.exists() or nested_lock.is_symlink():
                _error(
                    diagnostics,
                    "manifest.nested-lock",
                    "only the project root may contain .ctx/lock.json",
                    document,
                    path=nested_lock,
                )
    root_document = next(
        (
            value
            for value in documents
            if value.node_dir.resolve(strict=True) == root and value.manifest is not None
        ),
        None,
    )
    if root_document is not None:
        for index, alias in enumerate(project.aliases):
            normalized = normalize_alias(alias)
            compact = "".join(char for char in normalized if char.isalnum())
            if len(compact) < 3 or normalized in GENERIC_ALIASES:
                _warning(
                    diagnostics,
                    "alias.too-generic",
                    f"project alias is too generic for reliable lookup: {alias}",
                    root_document,
                    f"project.aliases[{index}]",
                    fails_strict=True,
                )


def _validate_artifacts(
    node: LoadedNode, root: Path, diagnostics: list[Diagnostic]
) -> None:
    manifest = node.manifest
    document = node.document
    declared: set[Path] = set()
    authored: dict[str, Path] = {}
    for index, artifact in enumerate(manifest.artifacts):
        field = f"artifacts[{index}].path"
        try:
            candidate = resolved_project_path(document.node_dir, artifact.path, root)
        except UnsafePathError as exc:
            _error(diagnostics, exc.code, exc.message, document, field)
            continue
        authored_candidate = lexical_project_path(document.node_dir, artifact.path, root)
        if is_secret_path(authored_candidate, root) or is_secret_path(candidate, root):
            _error(
                diagnostics,
                "artifact.secret",
                f"artifact path is reserved or may expose credentials: {artifact.path}",
                document,
                field,
                candidate,
            )
            continue
        if candidate in declared:
            _error(
                diagnostics,
                "artifact.duplicate",
                f"duplicate artifact path: {artifact.path}",
                document,
                field,
                candidate,
            )
        declared.add(candidate)
        authored[artifact.path] = candidate
        if not candidate.exists():
            _error(
                diagnostics,
                "artifact.missing",
                f"artifact does not exist: {artifact.path}",
                document,
                field,
                candidate,
            )
        elif not candidate.is_file():
            _error(
                diagnostics,
                "artifact.not-file",
                f"artifact is not a file: {artifact.path}",
                document,
                field,
                candidate,
            )
        elif not has_exact_case(candidate, root):
            _error(
                diagnostics,
                "artifact.case-mismatch",
                f"artifact path does not match filesystem case: {artifact.path}",
                document,
                field,
                candidate,
            )
    for item_index, item in enumerate(manifest.items):
        for artifact_index, artifact_path in enumerate(item.artifacts):
            try:
                resolved_project_path(
                    document.node_dir,
                    artifact_path,
                    root,
                    require_exists=False,
                )
            except UnsafePathError as exc:
                _error(
                    diagnostics,
                    exc.code,
                    exc.message,
                    document,
                    f"items[{item_index}].artifacts[{artifact_index}]",
                )
    for item_index, artifact_index, artifact_path, candidate in (
        find_undeclared_item_artifacts(
            manifest,
            document.node_dir,
            root,
            declared=declared,
        )
    ):
        _error(
            diagnostics,
            "item.artifact-undeclared",
            f"item artifact must also have a top-level artifact role: {artifact_path}",
            document,
            f"items[{item_index}].artifacts[{artifact_index}]",
            candidate,
        )


def find_undeclared_item_artifacts(
    manifest: Manifest,
    node_dir: Path,
    root: Path,
    *,
    declared: Iterable[Path] | None = None,
) -> tuple[tuple[int, int, str, Path], ...]:
    """Return safe item evidence paths lacking a top-level artifact role."""

    declared_paths: set[Path]
    if declared is None:
        declared_paths = set()
        for artifact in manifest.artifacts:
            try:
                declared_paths.add(
                    resolved_project_path(
                        node_dir,
                        artifact.path,
                        root,
                        require_exists=False,
                    )
                )
            except UnsafePathError:
                # The full validator reports unsafe artifact paths separately.
                continue
    else:
        declared_paths = set(declared)

    missing: list[tuple[int, int, str, Path]] = []
    for item_index, item in enumerate(manifest.items):
        for artifact_index, artifact_path in enumerate(item.artifacts):
            try:
                candidate = resolved_project_path(
                    node_dir,
                    artifact_path,
                    root,
                    require_exists=False,
                )
            except UnsafePathError:
                # Unsafe paths remain fatal whole-graph diagnostics, not
                # correctable model-output omissions.
                continue
            if candidate not in declared_paths:
                missing.append((item_index, artifact_index, artifact_path, candidate))
    return tuple(missing)


def _broad_tracking_pattern(value: str, document: ManifestDocument, root: Path) -> bool:
    if value in {"*", "**", "**/*"}:
        return True
    try:
        relative_node = document.node_dir.relative_to(root)
    except ValueError:
        return True
    parts = value.split("/")
    if any(part == ".." for part in parts) and "**" in parts:
        return True
    return not relative_node.parts and bool(parts) and any(char in parts[0] for char in "*?[")


def _glob_may_match_secret(value: str) -> bool:
    lowered = value.casefold()
    return (
        any(token in lowered for token in (".env", ".ssh", ".aws", ".git", ".ctx"))
        or any(lowered.endswith(suffix) for suffix in ("*.key", "*.pem", "*.p12", "*.pfx"))
        or "credential" in lowered
    )


def _validate_tracking(
    nodes: tuple[LoadedNode, ...], root: Path, diagnostics: list[Diagnostic]
) -> None:
    claimed: dict[Path, ManifestDocument] = {}
    for node in nodes:
        document = node.document
        include_candidates: set[Path] = set()
        exclude_candidates: set[Path] = set()
        for kind, values in (
            ("include", node.manifest.tracking.include),
            ("exclude", node.manifest.tracking.exclude),
        ):
            for index, value in enumerate(values):
                field = f"tracking.{kind}[{index}]"
                try:
                    candidate = require_safe_tracking_path(document.node_dir, value, root)
                except UnsafePathError as exc:
                    _error(diagnostics, exc.code, exc.message, document, field)
                    continue
                target_set = include_candidates if kind == "include" else exclude_candidates
                if candidate in target_set:
                    _error(
                        diagnostics,
                        "tracking.duplicate",
                        f"duplicate tracking {kind} path: {value}",
                        document,
                        field,
                    )
                target_set.add(candidate)
                if kind == "include" and (
                    is_secret_path(candidate, root) or _glob_may_match_secret(value)
                ):
                    _error(
                        diagnostics,
                        "tracking.secret",
                        f"tracking include is reserved or may expose credentials: {value}",
                        document,
                        field,
                        candidate,
                    )
                if _broad_tracking_pattern(value, document, root):
                    _warning(
                        diagnostics,
                        "tracking.glob-broad",
                        f"tracking glob may be unexpectedly broad: {value}",
                        document,
                        field,
                        fails_strict=True,
                    )
        for overlap in sorted(include_candidates & exclude_candidates):
            _error(
                diagnostics,
                "tracking.overlap",
                f"the same path is both included and excluded: {overlap.relative_to(root)}",
                document,
                "tracking",
                overlap,
            )
        for candidate in include_candidates:
            if any(char in str(candidate) for char in "*?["):
                continue
            owner = claimed.get(candidate)
            if owner is not None and owner.path != document.path:
                _error(
                    diagnostics,
                    "tracking.ownership-conflict",
                    f"tracking include is already claimed by {owner.path}",
                    document,
                    "tracking.include",
                    candidate,
                )
            claimed[candidate] = document


def _target_node_reference(uri: ContextUri) -> str:
    return str(ContextUri(uri.project_id, uri.node_ids))


def _validate_links(
    nodes: tuple[LoadedNode, ...], project: Project, diagnostics: list[Diagnostic]
) -> None:
    by_uri = {node.uri: node for node in nodes}
    item_uris = {
        item_uri(node.uri, item.id): (node, item)
        for node in nodes
        for item in node.manifest.items
    }
    supersession_edges: dict[str, list[str]] = {}
    supersession_documents: dict[str, ManifestDocument] = {}
    for node in nodes:
        for index, link in enumerate(node.manifest.links):
            field = f"links[{index}].target"
            try:
                target = parse_ctx_uri(link.target)
            except CtxError as exc:
                _error(diagnostics, exc.code, exc.message, node.document, field)
                continue
            if target.project_id != project.id:
                _warning(
                    diagnostics,
                    "link.external-deferred",
                    f"external link resolution is deferred until registry resolution: {link.target}",
                    node.document,
                    field,
                    fails_strict=False,
                )
                continue
            target_node_uri = _target_node_reference(target)
            found = target_node_uri in by_uri and (
                target.item_id is None
                or str(target) in item_uris
            )
            if not found:
                if link.optional:
                    _warning(
                        diagnostics,
                        "link.optional-unresolved",
                        f"optional link is unresolved: {link.target}",
                        node.document,
                        field,
                        fails_strict=False,
                    )
                else:
                    _error(
                        diagnostics,
                        "link.unresolved",
                        f"required link is unresolved: {link.target}",
                        node.document,
                        field,
                    )
            if target.item_id is None and target_node_uri == node.uri:
                _error(
                    diagnostics,
                    "link.self",
                    f"node cannot link to itself: {link.target}",
                    node.document,
                    field,
                )
            if link.relation == "supersedes" and found:
                source = node.uri
                target_reference = str(target)
                supersession_edges.setdefault(source, []).append(target_reference)
                supersession_documents[source] = node.document
        for item_index, item in enumerate(node.manifest.items):
            if item.kind != "decision":
                continue
            source = item_uri(node.uri, item.id)
            for reference_index, reference in enumerate(item.supersedes):
                field = f"items[{item_index}].supersedes[{reference_index}]"
                if reference.startswith("ctx://"):
                    try:
                        parsed = parse_ctx_uri(reference)
                    except CtxError as exc:
                        _error(diagnostics, exc.code, exc.message, node.document, field)
                        continue
                    if parsed.project_id != project.id:
                        _warning(
                            diagnostics,
                            "supersedes.external-deferred",
                            f"external supersession resolution is deferred: {reference}",
                            node.document,
                            field,
                            fails_strict=False,
                        )
                        continue
                    target = str(parsed)
                else:
                    target_id = reference[1:] if reference.startswith("#") else reference
                    try:
                        target = item_uri(node.uri, target_id)
                    except CtxError as exc:
                        _error(diagnostics, exc.code, exc.message, node.document, field)
                        continue
                if target == source:
                    _error(
                        diagnostics,
                        "supersedes.self",
                        "a decision cannot supersede itself",
                        node.document,
                        field,
                    )
                elif target not in item_uris:
                    _error(
                        diagnostics,
                        "supersedes.unresolved",
                        f"superseded item is unresolved: {reference}",
                        node.document,
                        field,
                    )
                else:
                    supersession_edges.setdefault(source, []).append(target)
                    supersession_documents[source] = node.document
    state: dict[str, int] = {}
    cycle_source: str | None = None
    for origin in sorted(supersession_edges):
        if state.get(origin) == 2:
            continue
        stack: list[tuple[str, int]] = [(origin, 0)]
        while stack and cycle_source is None:
            current, next_index = stack[-1]
            if state.get(current, 0) == 0:
                state[current] = 1
            targets = supersession_edges.get(current, ())
            if next_index >= len(targets):
                state[current] = 2
                stack.pop()
                continue
            target = targets[next_index]
            stack[-1] = (current, next_index + 1)
            target_state = state.get(target, 0)
            if target_state == 1:
                cycle_source = current
                break
            if target_state == 0:
                stack.append((target, 0))
        if cycle_source is not None:
            document = supersession_documents[cycle_source]
            _error(
                diagnostics,
                "supersedes.cycle",
                f"supersession cycle includes {cycle_source}",
                document,
            )
            break


def _validate_root_lock(
    root: Path,
    project: Project,
    nodes: tuple[LoadedNode, ...],
    documents: tuple[ManifestDocument, ...],
    diagnostics: list[Diagnostic],
) -> None:
    path = root / ".ctx" / "lock.json"
    if not path.exists() and not path.is_symlink():
        return
    document = next(
        (value for value in documents if value.node_dir.resolve(strict=True) == root),
        documents[0],
    )
    if path.is_symlink():
        _error(diagnostics, "lock.symlink", "root lock cannot be a symlink", document, path=path)
        return
    try:
        metadata = path.stat()
        if not path.is_file():
            _error(diagnostics, "lock.not-file", "root lock must be a regular file", document, path=path)
            return
        if metadata.st_size > MAX_LOCK_BYTES:
            _error(diagnostics, "lock.too-large", "root lock exceeds its safety limit", document, path=path)
            return
        raw = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _error(diagnostics, "lock.invalid", f"root lock is invalid JSON: {exc}", document, path=path)
        return
    if type(raw) is not dict or set(raw) != {"schema", "project_id", "nodes"}:
        _error(diagnostics, "lock.invalid", "root lock has invalid fields", document, path=path)
        return
    if raw.get("schema") != "ctx-lock/v1" or raw.get("project_id") != project.id or type(raw.get("nodes")) is not dict:
        _error(diagnostics, "lock.invalid", "root lock schema or project identity is invalid", document, path=path)
        return
    known = {node.uri for node in nodes}
    for uri, value in sorted(raw["nodes"].items()):
        if uri not in known:
            _warning(
                diagnostics,
                "lock.unknown-node",
                f"lock references removed node {uri}; status will report the lock stale",
                document,
                fails_strict=False,
            )
            continue
        if type(value) is not dict or set(value) != {"source_fingerprint", "context_fingerprint"}:
            _error(diagnostics, "lock.invalid-entry", f"lock entry is invalid for {uri}", document, path=path)
            continue
        if any(
            type(value[key]) is not str or LOCK_FINGERPRINT.fullmatch(value[key]) is None
            for key in ("source_fingerprint", "context_fingerprint")
        ):
            _error(diagnostics, "lock.invalid-fingerprint", f"lock fingerprint is invalid for {uri}", document, path=path)


def validate_documents(
    input_path: Path,
    project_root: Path,
    project: Project,
    documents: tuple[ManifestDocument, ...],
    *,
    strict: bool = False,
) -> ValidationResult:
    root = project_root.resolve(strict=True)
    diagnostics: list[Diagnostic] = []
    for document in documents:
        diagnostics.extend(document.diagnostics)
    nodes = assign_node_uris(root, project, documents)
    _validate_root_rules(root, project, documents, diagnostics)
    by_uri: dict[str, LoadedNode] = {}
    for node in nodes:
        existing = by_uri.get(node.uri)
        if existing is not None:
            _error(
                diagnostics,
                "node.uri-collision",
                f"semantic node URI collides with {existing.document.path}: {node.uri}",
                node.document,
                "node.id",
            )
            _error(
                diagnostics,
                "node.uri-collision",
                f"semantic node URI collides with {node.document.path}: {node.uri}",
                existing.document,
                "node.id",
            )
        by_uri[node.uri] = node
        _validate_artifacts(node, root, diagnostics)
    _validate_tracking(nodes, root, diagnostics)
    _validate_links(nodes, project, diagnostics)
    _validate_root_lock(root, project, nodes, documents, diagnostics)
    diagnostics.sort(key=Diagnostic.sort_key)
    return ValidationResult(
        input_path.resolve(strict=True),
        root,
        project,
        nodes,
        tuple(diagnostics),
        strict,
    )


def validate_project(path: Path, *, strict: bool = False) -> ValidationResult:
    root, project = find_project_root(path)
    documents = scan_project_documents(root)
    return validate_documents(path, root, project, documents, strict=strict)
