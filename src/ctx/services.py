from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .diagnostics import CtxError, Diagnostic, NotFoundError, UnsafePathError
from .discovery import (
    Ancestry,
    assign_node_uris,
    discover_ancestry,
    find_project_root,
    manifest_path,
    read_manifest_document,
    scan_project_documents,
)
from .models import Manifest, Node, Project
from .paths import (
    absolute_lexical,
    existing_directory,
    is_within,
    lexical_project_path,
    normalize_alias,
    require_safe_context_file,
    slugify,
)
from .schema import diagnostic_errors
from .uri import node_uri, parse_ctx_uri, require_id
from .validation import ValidationResult, validate_project
from .yamlio import create_text_atomic, dump_yaml


@dataclass(frozen=True, slots=True)
class MutationResult:
    action: str
    manifest_path: Path


@dataclass(frozen=True, slots=True)
class ShowResult:
    ancestry: Ancestry
    diagnostics: tuple[Diagnostic, ...]
    selected_uri: str | None = None
    selected_item: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        ancestry = self.ancestry
        rendered_nodes: list[dict[str, Any]] = []
        for loaded in ancestry.nodes:
            document = loaded.document
            manifest = loaded.manifest
            modeled = manifest.to_dict()
            artifacts: list[dict[str, Any]] = []
            for artifact in manifest.artifacts:
                absolute = lexical_project_path(
                    document.node_dir, artifact.path, ancestry.project_root
                )
                artifacts.append(
                    {
                        "path": artifact.path,
                        "role": artifact.role,
                        "absolute_path": str(absolute),
                    }
                )
            tracking = modeled.get("tracking", {})
            rendered_nodes.append(
                {
                    "uri": loaded.uri,
                    "directory": str(document.node_dir),
                    "manifest": str(document.path),
                    "node": modeled["node"],
                    "artifacts": artifacts,
                    "items": modeled.get("items", []),
                    "links": modeled.get("links", []),
                    "tracking": {
                        "include": tracking.get("include", []),
                        "exclude": tracking.get("exclude", []),
                    },
                }
            )
        result = {
            "schema": "ctx-show/v1",
            "reference": str(ancestry.requested_path),
            "resolved_path": str(ancestry.resolved_path),
            "project": {
                "id": ancestry.project.id,
                "name": ancestry.project.name,
                "aliases": list(ancestry.project.aliases),
                "root": str(ancestry.project_root),
            },
            "current_node_uri": ancestry.current.uri,
            "nodes": rendered_nodes,
            "validation": {
                "valid": True,
                "errors": 0,
                "warnings": sum(
                    value.severity == "warning" for value in self.diagnostics
                ),
            },
            "diagnostics": [value.to_dict() for value in self.diagnostics],
        }
        if self.selected_uri is not None:
            result["selected_uri"] = self.selected_uri
        if self.selected_item is not None:
            result["selected_item"] = self.selected_item
        return result


def _validate_aliases(aliases: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for alias in aliases:
        if type(alias) is not str or not alias.strip():
            raise CtxError("alias.invalid", "aliases must be non-empty strings", exit_code=1)
        normalized = normalize_alias(alias)
        if normalized in seen:
            raise CtxError("alias.duplicate", f"duplicate alias: {alias}", exit_code=1)
        seen.add(normalized)
        result.append(alias)
    return tuple(result)


def _existing_manifest(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _assert_valid_existing(path: Path) -> Manifest:
    require_safe_context_file(path)
    document = read_manifest_document(path)
    if document.manifest is None or diagnostic_errors(document.diagnostics):
        detail = next(
            (
                diagnostic.message
                for diagnostic in document.diagnostics
                if diagnostic.severity == "error"
            ),
            "manifest is invalid",
        )
        raise CtxError(
            "manifest.invalid",
            f"existing manifest was not changed because it is invalid: {detail}",
            exit_code=1,
        )
    return document.manifest


def init_project(
    path: Path,
    *,
    project_id: str | None = None,
    name: str | None = None,
    aliases: Iterable[str] = (),
) -> MutationResult:
    target = existing_directory(path)
    if target.is_symlink():
        raise UnsafePathError(
            "project.symlink-target",
            f"project initialization target cannot be a symlink: {target}",
        )
    output = manifest_path(target)
    supplied_aliases = _validate_aliases(aliases)
    if project_id is not None:
        require_id(project_id, "project ID")
    if name is not None and not name.strip():
        raise CtxError("project.name-invalid", "project name cannot be empty", exit_code=1)
    if _existing_manifest(output):
        existing = _assert_valid_existing(output)
        if existing.project is None or existing.node.id != "root":
            raise CtxError(
                "manifest.conflict",
                f"existing manifest is not a valid project root and was not changed: {output}",
                exit_code=1,
            )
        conflicts = (
            (project_id is not None and existing.project.id != project_id)
            or (name is not None and existing.project.name != name)
            or any(
                normalize_alias(alias)
                not in {normalize_alias(value) for value in existing.project.aliases}
                for alias in supplied_aliases
            )
        )
        if conflicts:
            raise CtxError(
                "manifest.conflict",
                f"existing manifest has different identity and was not changed: {output}",
                exit_code=1,
            )
        return MutationResult("unchanged", output)
    require_safe_context_file(output)
    descendant_manifests = tuple(
        candidate
        for candidate in target.rglob(".ctx/context.yaml")
        if candidate != output
    )
    if descendant_manifests:
        raise CtxError(
            "project.descendant-context",
            "cannot initialize around existing descendant context manifest: "
            f"{sorted(descendant_manifests, key=str)[0]}",
            exit_code=1,
        )
    try:
        enclosing_root, _project = find_project_root(target.parent)
    except NotFoundError:
        enclosing_root = None
    if enclosing_root is not None and is_within(target.resolve(strict=True), enclosing_root):
        raise CtxError(
            "project.nested",
            f"cannot initialize a project inside existing ctx project {enclosing_root}; use 'ctx node init'",
            exit_code=1,
        )
    project_name = name if name is not None else target.name
    if not project_name.strip():
        raise CtxError(
            "project.name-invalid",
            "cannot infer a project name from this path; pass --name",
            exit_code=1,
        )
    derived_id = slugify(target.name)
    selected_id = project_id if project_id is not None else derived_id
    if not selected_id:
        raise CtxError(
            "identity.required",
            "cannot infer a project ID from the directory name; pass --id",
            exit_code=1,
        )
    require_id(selected_id, "project ID")
    manifest = Manifest(
        version=1,
        project=Project(selected_id, project_name, supplied_aliases),
        node=Node("root", project_name),
    )
    create_text_atomic(output, dump_yaml(manifest.to_dict()))
    return MutationResult("created", output)


def init_node(
    path: Path,
    *,
    node_id: str,
    name: str,
    summary: str | None = None,
) -> MutationResult:
    target = existing_directory(path)
    require_id(node_id, "node ID")
    if node_id == "root":
        raise CtxError("identity.reserved", "nested node ID cannot be 'root'", exit_code=1)
    if not name.strip():
        raise CtxError("node.name-invalid", "node name cannot be empty", exit_code=1)
    if summary is not None and not summary.strip():
        raise CtxError("node.summary-invalid", "node summary cannot be empty", exit_code=1)
    root, project = find_project_root(target)
    resolved_target = target.resolve(strict=True)
    if resolved_target == root:
        raise CtxError(
            "node.at-root",
            "the project root is already a node; use 'ctx init' there",
            exit_code=1,
        )
    relative = resolved_target.relative_to(root)
    if any(part in {".ctx", ".git"} for part in relative.parts):
        raise UnsafePathError(
            "node.reserved-path", "cannot create a semantic node inside .ctx or .git"
        )
    output = manifest_path(resolved_target)
    if _existing_manifest(output):
        existing = _assert_valid_existing(output)
        if existing.project is not None:
            raise CtxError(
                "manifest.conflict",
                f"existing manifest redefines project identity and was not changed: {output}",
                exit_code=1,
            )
        conflicts = (
            existing.node.id != node_id
            or existing.node.name != name
            or (summary is not None and existing.node.summary != summary)
        )
        if conflicts:
            raise CtxError(
                "manifest.conflict",
                f"existing manifest has different node identity and was not changed: {output}",
                exit_code=1,
            )
        return MutationResult("unchanged", output)
    require_safe_context_file(output)
    ancestry = discover_ancestry(resolved_target)
    parent_ids = parse_ctx_uri(ancestry.current.uri).node_ids
    prospective_uri = node_uri(project.id, parent_ids + (node_id,))
    documents = scan_project_documents(root)
    for loaded in assign_node_uris(root, project, documents):
        if loaded.uri == prospective_uri:
            raise CtxError(
                "node.uri-collision",
                f"node URI {prospective_uri} is already defined by {loaded.document.path}",
                exit_code=1,
            )
    manifest = Manifest(
        version=1,
        node=Node(node_id, name, summary),
    )
    create_text_atomic(output, dump_yaml(manifest.to_dict()))
    return MutationResult("created", output)


def show(reference: str) -> ShowResult:
    selected_uri: str | None = None
    selected_item: dict[str, Any] | None = None
    candidate = Path(reference)
    if candidate.exists():
        ancestry = discover_ancestry(candidate)
    else:
        # Imported lazily so local foundation services do not depend on global
        # registry state unless the caller actually supplies a symbolic/URI
        # reference.
        from .universe import resolve_reference

        selected = resolve_reference(reference)
        ancestry = discover_ancestry(selected.node.document.node_dir)
        selected_uri = selected.uri
        if selected.item is not None:
            selected_item = next(
                value
                for value in selected.node.manifest.to_dict().get("items", [])
                if value["id"] == selected.item.id
            )
    validation = validate_project(ancestry.project_root)
    chain_paths = {node.document.path for node in ancestry.nodes}
    relevant = tuple(
        diagnostic
        for diagnostic in validation.diagnostics
        if diagnostic.manifest is None or diagnostic.manifest in chain_paths
    )
    errors = [value for value in relevant if value.severity == "error"]
    if errors:
        unsafe_prefixes = (
            "path.",
            "artifact.secret",
            "tracking.secret",
            "manifest.symlink",
            "manifest.nested-lock",
            "lock.symlink",
        )
        unsafe = any(
            value.code.startswith(unsafe_prefixes)
            for value in errors
        )
        raise CtxError(
            "context.invalid",
            f"cannot show invalid context: {errors[0].message}",
            exit_code=3 if unsafe else 1,
        )
    return ShowResult(ancestry, relevant, selected_uri, selected_item)


def validation_to_dict(result: ValidationResult) -> dict[str, Any]:
    node_error_paths = {
        diagnostic.manifest
        for diagnostic in result.diagnostics
        if diagnostic.severity == "error"
        or (result.strict and diagnostic.severity == "warning" and diagnostic.fails_strict)
    }
    return {
        "schema": "ctx-validation/v1",
        "path": str(result.input_path),
        "project": {"id": result.project.id, "root": str(result.project_root)},
        "strict": result.strict,
        "valid": result.valid,
        "nodes": [
            {
                "uri": node.uri,
                "manifest": str(node.document.path),
                "valid": node.document.path not in node_error_paths,
            }
            for node in result.nodes
        ],
        "diagnostics": [value.to_dict() for value in result.diagnostics],
        "summary": {
            "nodes": len(result.nodes),
            "errors": len(result.errors),
            "warnings": len(result.warnings),
            "strict_failures": len(result.strict_failures),
        },
    }
