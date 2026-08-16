from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .diagnostics import CtxError, NotFoundError, UnsafePathError
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
    trust: str
    reuse_policy: str
    match_kind: str
    matched_field: str
    matched_tokens: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "uri": self.uri,
            "title": self.title,
            "summary": self.summary,
            "project": self.project_id,
            "node": self.node_name,
            "kind": self.kind,
            "score": self.score,
            "trust": self.trust,
            "reuse_policy": self.reuse_policy,
            "match": {
                "kind": self.match_kind,
                "field": self.matched_field,
                "tokens": list(self.matched_tokens),
            },
        }


@dataclass(frozen=True, slots=True)
class _SearchMatch:
    score: int
    kind: str
    field: str
    tokens: tuple[str, ...]


def require_context_reuse(entry: RegistryEntry) -> None:
    """Enforce the registry's hard deny before reading project context."""

    if entry.reuse_policy == "prohibited":
        raise UnsafePathError(
            "policy.prohibited",
            f"registered project {entry.project_id} prohibits context reuse",
        )


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
        entries = tuple(
            entry
            for entry in selected.projects
            if entry.reuse_policy != "prohibited"
        )
    else:
        entry = resolve_project(project, registry=selected)
        require_context_reuse(entry)
        entries = (entry,)
    return tuple(_load_indexed(entry) for entry in entries)


def indexed_project_for_root(
    root: Path, *, registry: Registry | None = None
) -> IndexedProject:
    """Resolve an external checkout only through an exact registry root."""

    selected = registry or load_registry()
    try:
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UnsafePathError(
            "reference.external-path-unsafe",
            f"external context path is unavailable: {root}",
        ) from exc
    matches: list[RegistryEntry] = []
    for entry in selected.projects:
        try:
            entry_root = entry.root.resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        if entry_root == resolved_root:
            matches.append(entry)
    if not matches:
        raise UnsafePathError(
            "reference.external-path-unregistered",
            "external filesystem context must belong to an exact registered checkout: "
            f"{resolved_root}",
        )
    if len(matches) > 1:
        raise UnsafePathError(
            "registry.root-conflict",
            f"external checkout is registered more than once: {resolved_root}",
        )
    entry = matches[0]
    require_context_reuse(entry)
    return _load_indexed(entry)


def indexed_project_for_path(
    path: Path, *, registry: Registry | None = None
) -> IndexedProject:
    """Gate an external path through its nearest containing registered checkout."""

    selected = registry or load_registry()
    try:
        resolved_path = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UnsafePathError(
            "reference.external-path-unsafe",
            f"external context path is unavailable: {path}",
        ) from exc
    matches: list[tuple[int, RegistryEntry]] = []
    for entry in selected.projects:
        try:
            entry_root = entry.root.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved_path == entry_root or resolved_path.is_relative_to(entry_root):
            matches.append((len(entry_root.parts), entry))
    if not matches:
        raise UnsafePathError(
            "reference.external-path-unregistered",
            "external filesystem context must belong to a registered checkout: "
            f"{resolved_path}",
        )
    depth = max(value[0] for value in matches)
    leaders = [entry for candidate_depth, entry in matches if candidate_depth == depth]
    if len(leaders) != 1:
        raise UnsafePathError(
            "registry.root-conflict",
            f"external path belongs to multiple registered checkouts: {resolved_path}",
        )
    entry = leaders[0]
    require_context_reuse(entry)
    return _load_indexed(entry)


def _node_by_uri(indexed: IndexedProject, node_uri: str) -> LoadedNode:
    match = next((node for node in indexed.validation.nodes if node.uri == node_uri), None)
    if match is None:
        raise NotFoundError("reference.unresolved", f"no context node exists at {node_uri}")
    return match


def resolve_uri(reference: str, *, registry: Registry | None = None) -> ResolvedContext:
    parsed = parse_ctx_uri(reference)
    selected = registry or load_registry()
    entry = resolve_project(parsed.project_id, registry=selected)
    require_context_reuse(entry)
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
    needle = _normalized(reference)
    for entry in registry.projects:
        project_keys = {
            _normalized(entry.project_id),
            _normalized(entry.name),
            *(_normalized(value) for value in entry.aliases),
        }
        if needle in project_keys and entry.reuse_policy == "prohibited":
            require_context_reuse(entry)
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


def _score(
    query: str,
    fields: tuple[tuple[str, str], ...],
    *,
    identities: tuple[tuple[str, str], ...],
    titles: tuple[tuple[str, str], ...],
) -> _SearchMatch | None:
    normalized_query = _normalized(query)
    query_tokens = set(normalized_query.split())
    if not normalized_query:
        return None

    for field, value in identities:
        normalized = _normalized(value)
        if normalized_query == normalized:
            return _SearchMatch(
                10_000,
                "identity-exact",
                field,
                tuple(sorted(query_tokens)),
            )
    for field, value in titles:
        normalized = _normalized(value)
        if normalized_query == normalized:
            return _SearchMatch(
                9_000,
                "title-exact",
                field,
                tuple(sorted(query_tokens)),
            )
    for field, value in identities:
        normalized = _normalized(value)
        if normalized.startswith(normalized_query):
            return _SearchMatch(
                7_000,
                "identity-prefix",
                field,
                tuple(sorted(query_tokens)),
            )
    for field, value in titles:
        normalized = _normalized(value)
        if normalized.startswith(normalized_query):
            return _SearchMatch(
                6_000,
                "title-prefix",
                field,
                tuple(sorted(query_tokens)),
            )

    best: _SearchMatch | None = None
    for field, value in fields:
        normalized = _normalized(value)
        field_tokens = set(normalized.split())
        matched_tokens = tuple(sorted(query_tokens & field_tokens))
        overlap = len(matched_tokens)
        padded_query = f" {normalized_query} "
        padded_field = f" {normalized} "
        if normalized_query and padded_query in padded_field:
            candidate = _SearchMatch(
                4_500 + overlap * 100,
                "field-phrase",
                field,
                matched_tokens,
            )
        elif query_tokens and query_tokens.issubset(field_tokens):
            candidate = _SearchMatch(
                4_000 + overlap * 100,
                "field-all-tokens",
                field,
                matched_tokens,
            )
        elif query_tokens and all(
            any(field_token.startswith(query_token) for field_token in field_tokens)
            for query_token in query_tokens
        ):
            candidate = _SearchMatch(
                3_000 + overlap * 100,
                "field-token-prefix",
                field,
                matched_tokens,
            )
        elif overlap:
            candidate = _SearchMatch(
                overlap * 100,
                "field-token-overlap",
                field,
                matched_tokens,
            )
        else:
            continue
        if best is None or candidate.score > best.score:
            best = candidate
    return best


def search_context(
    query: str, *, project: str | None = None, limit: int = 50
) -> tuple[SearchHit, ...]:
    if not query.strip():
        raise CtxError("search.query-required", "search query cannot be empty", exit_code=1)
    hits: list[SearchHit] = []
    for indexed in indexed_projects(project=project):
        entry = indexed.entry
        for node in indexed.validation.nodes:
            manifest = node.manifest
            is_root = node.uri == f"ctx://{indexed.validation.project.id}"
            node_fields: list[tuple[str, str]] = [
                ("node.id", manifest.node.id),
                ("node.name", manifest.node.name),
                ("node.summary", manifest.node.summary or ""),
                *(("artifact.path", artifact.path) for artifact in manifest.artifacts),
                *(("artifact.role", artifact.role) for artifact in manifest.artifacts),
            ]
            node_identities: list[tuple[str, str]] = [("node.id", manifest.node.id)]
            node_titles: list[tuple[str, str]] = [("node.name", manifest.node.name)]
            if is_root:
                node_identities.extend(
                    [("project.id", entry.project_id)]
                    + [("project.alias", value) for value in entry.aliases]
                )
                node_titles.append(("project.name", entry.name))
                node_fields.extend(
                    [
                        ("project.id", entry.project_id),
                        ("project.name", entry.name),
                        *(("project.alias", value) for value in entry.aliases),
                    ]
                )
            node_match = _score(
                query,
                tuple(node_fields),
                identities=tuple(node_identities),
                titles=tuple(node_titles),
            )
            if node_match is not None:
                hits.append(
                    SearchHit(
                        node.uri,
                        manifest.node.name,
                        manifest.node.summary or "",
                        entry.project_id,
                        manifest.node.name,
                        "node",
                        node_match.score,
                        entry.trust,
                        entry.reuse_policy,
                        node_match.kind,
                        node_match.field,
                        node_match.tokens,
                    )
                )
            for item in manifest.items:
                item_match = _score(
                    query,
                    (
                        ("item.id", item.id),
                        ("item.kind", item.kind),
                        ("item.title", item.title),
                        ("item.summary", item.summary),
                        ("item.reason", item.reason or ""),
                    ),
                    identities=(("item.id", item.id),),
                    titles=(("item.title", item.title),),
                )
                if item_match is not None:
                    hits.append(
                        SearchHit(
                            item_uri(node.uri, item.id),
                            item.title,
                            item.summary,
                            entry.project_id,
                            manifest.node.name,
                            item.kind,
                            item_match.score,
                            entry.trust,
                            entry.reuse_policy,
                            item_match.kind,
                            item_match.field,
                            item_match.tokens,
                        )
                    )
    hits.sort(key=lambda value: (-value.score, value.uri, value.kind, value.title))
    return tuple(hits[:limit])
