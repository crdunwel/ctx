from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .diagnostics import CtxError, NotFoundError
from .models import Item, LoadedNode
from .registry import Registry, RegistryEntry, load_registry, resolve_project
from .uri import ContextUri, item_uri, parse_ctx_uri
from .validation import ValidationResult, validate_project


TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True, slots=True)
class IndexedProject:
    entry: RegistryEntry
    validation: ValidationResult


@dataclass(frozen=True, slots=True)
class ResolvedContext:
    project: IndexedProject
    node: LoadedNode
    item: Item | None = None

    @property
    def uri(self) -> str:
        return self.node.uri if self.item is None else item_uri(self.node.uri, self.item.id)

    def to_dict(self) -> dict[str, Any]:
        manifest = self.node.manifest
        value: dict[str, Any] = {
            "schema": "ctx-resolution/v1",
            "uri": self.uri,
            "project": {
                "id": self.project.entry.project_id,
                "name": self.project.entry.name,
                "aliases": list(self.project.entry.aliases),
                "root": str(self.project.entry.root),
                "trust": self.project.entry.trust,
                "reuse_policy": self.project.entry.reuse_policy,
            },
            "node": {
                "id": manifest.node.id,
                "name": manifest.node.name,
                "summary": manifest.node.summary,
                "directory": str(self.node.document.node_dir),
                "manifest": str(self.node.document.path),
                "artifacts": [
                    {
                        "path": value.path,
                        "role": value.role,
                        "absolute_path": str(
                            (self.node.document.node_dir / value.path).resolve(strict=False)
                        ),
                    }
                    for value in manifest.artifacts
                ],
            },
        }
        if self.item is not None:
            rendered = next(
                raw for raw in manifest.to_dict().get("items", []) if raw["id"] == self.item.id
            )
            value["item"] = rendered
        return value


@dataclass(frozen=True, slots=True)
class SearchHit:
    uri: str
    title: str
    summary: str
    project_id: str
    node_name: str
    kind: str
    score: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "uri": self.uri,
            "title": self.title,
            "summary": self.summary,
            "project": self.project_id,
            "node": self.node_name,
            "kind": self.kind,
            "score": self.score,
        }


def _load_indexed(entry: RegistryEntry, *, strict: bool = False) -> IndexedProject:
    if not entry.root.exists() or not entry.root.is_dir():
        raise NotFoundError(
            "registry.stale-root", f"registered project root is unavailable: {entry.root}"
        )
    if entry.root.is_symlink():
        raise CtxError(
            "registry.unsafe-root",
            f"registered project root became a symlink: {entry.root}",
            exit_code=3,
        )
    result = validate_project(entry.root, strict=strict)
    if not result.valid:
        first = (result.errors or result.strict_failures)[0]
        raise CtxError(
            "project.invalid",
            f"registered project {entry.project_id} is invalid: {first.code}: {first.message}",
            exit_code=3 if result.unsafe else 1,
        )
    if result.project.id != entry.project_id:
        raise NotFoundError(
            "registry.identity-changed",
            f"registered checkout at {entry.root} now identifies as {result.project.id}",
        )
    return IndexedProject(entry, result)


def indexed_projects(
    *, registry: Registry | None = None, project: str | None = None
) -> tuple[IndexedProject, ...]:
    selected = registry or load_registry()
    entries: Iterable[RegistryEntry]
    if project is None:
        entries = selected.projects
    else:
        entries = (resolve_project(project, registry=selected),)
    return tuple(_load_indexed(entry) for entry in entries)


def _node_by_uri(indexed: IndexedProject, node_uri: str) -> LoadedNode:
    match = next((node for node in indexed.validation.nodes if node.uri == node_uri), None)
    if match is None:
        raise NotFoundError("reference.unresolved", f"no context node exists at {node_uri}")
    return match


def resolve_uri(reference: str, *, registry: Registry | None = None) -> ResolvedContext:
    parsed = parse_ctx_uri(reference)
    selected = registry or load_registry()
    entry = resolve_project(parsed.project_id, registry=selected)
    indexed = _load_indexed(entry)
    node_reference = str(ContextUri(parsed.project_id, parsed.node_ids))
    node = _node_by_uri(indexed, node_reference)
    if parsed.item_id is None:
        return ResolvedContext(indexed, node)
    item = next((value for value in node.manifest.items if value.id == parsed.item_id), None)
    if item is None:
        raise NotFoundError("reference.unresolved", f"no context item exists at {reference}")
    return ResolvedContext(indexed, node, item)


def _normalized(value: str) -> str:
    return " ".join(TOKEN_PATTERN.findall(value.casefold()))


def _exact_candidates(reference: str, projects: Iterable[IndexedProject]) -> list[ResolvedContext]:
    needle = _normalized(reference)
    matches: list[ResolvedContext] = []
    for indexed in projects:
        project = indexed.validation.project
        project_keys = {_normalized(project.id), _normalized(project.name)} | {
            _normalized(value) for value in project.aliases
        }
        if needle in project_keys:
            root = next(node for node in indexed.validation.nodes if node.uri == f"ctx://{project.id}")
            matches.append(ResolvedContext(indexed, root))
        for node in indexed.validation.nodes:
            node_keys = {_normalized(node.manifest.node.id), _normalized(node.manifest.node.name)}
            if needle in node_keys:
                matches.append(ResolvedContext(indexed, node))
            for item in node.manifest.items:
                if needle in {_normalized(item.id), _normalized(item.title)}:
                    matches.append(ResolvedContext(indexed, node, item))
    deduplicated = {match.uri: match for match in matches}
    return [deduplicated[key] for key in sorted(deduplicated)]


def resolve_reference(reference: str, *, project: str | None = None) -> ResolvedContext:
    if reference.startswith("ctx://"):
        return resolve_uri(reference)
    registry = load_registry()
    projects = indexed_projects(registry=registry, project=project)
    matches = _exact_candidates(reference, projects)
    if not matches:
        raise NotFoundError("reference.unresolved", f"no context matches {reference!r}")
    if len(matches) > 1:
        candidates = ", ".join(value.uri for value in matches[:8])
        raise NotFoundError(
            "reference.ambiguous", f"reference {reference!r} is ambiguous: {candidates}"
        )
    return matches[0]


def _score(query: str, fields: tuple[str, ...], *, identity: str, title: str) -> int:
    normalized_query = _normalized(query)
    query_tokens = set(normalized_query.split())
    normalized_identity = _normalized(identity)
    normalized_title = _normalized(title)
    if normalized_query == normalized_identity:
        return 10_000
    if normalized_query == normalized_title:
        return 9_000
    if normalized_identity.startswith(normalized_query):
        return 7_000
    if normalized_title.startswith(normalized_query):
        return 6_000
    field_tokens = set()
    haystack = ""
    for field in fields:
        normalized = _normalized(field)
        field_tokens.update(normalized.split())
        haystack += " " + normalized
    overlap = len(query_tokens & field_tokens)
    if query_tokens and query_tokens.issubset(field_tokens):
        return 4_000 + overlap * 100
    if normalized_query and normalized_query in haystack:
        return 2_000 + overlap * 100
    return overlap * 100


def search_context(query: str, *, project: str | None = None, limit: int = 50) -> tuple[SearchHit, ...]:
    if not query.strip():
        raise CtxError("search.query-required", "search query cannot be empty", exit_code=1)
    hits: list[SearchHit] = []
    for indexed in indexed_projects(project=project):
        entry = indexed.entry
        for node in indexed.validation.nodes:
            manifest = node.manifest
            node_score = _score(
                query,
                (
                    entry.project_id,
                    entry.name,
                    *entry.aliases,
                    manifest.node.id,
                    manifest.node.name,
                    manifest.node.summary or "",
                    *(artifact.path for artifact in manifest.artifacts),
                    *(artifact.role for artifact in manifest.artifacts),
                ),
                identity=manifest.node.id,
                title=manifest.node.name,
            )
            if node_score:
                hits.append(
                    SearchHit(
                        node.uri,
                        manifest.node.name,
                        manifest.node.summary or "",
                        entry.project_id,
                        manifest.node.name,
                        "node",
                        node_score,
                    )
                )
            for item in manifest.items:
                item_score = _score(
                    query,
                    (item.id, item.kind, item.title, item.summary, item.reason or ""),
                    identity=item.id,
                    title=item.title,
                )
                if item_score:
                    hits.append(
                        SearchHit(
                            item_uri(node.uri, item.id),
                            item.title,
                            item.summary,
                            entry.project_id,
                            manifest.node.name,
                            item.kind,
                            item_score,
                        )
                    )
    hits.sort(key=lambda value: (-value.score, value.uri, value.kind, value.title))
    return tuple(hits[:limit])
