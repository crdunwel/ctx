from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .diagnostics import CtxError
from .discovery import discover_ancestry
from .models import LoadedNode
from .registry import RegistryEntry
from .universe import IndexedProject, ResolvedContext, resolve_reference, resolve_uri
from .uri import ContextUri, parse_ctx_uri
from .validation import validate_project


MAX_GRAPH_DEPTH = 8
MAX_GRAPH_NODES = 200


@dataclass(frozen=True, slots=True)
class GraphEdge:
    source: str
    target: str
    relation: str
    optional: bool
    resolved: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "optional": self.optional,
            "resolved": self.resolved,
        }


@dataclass(frozen=True, slots=True)
class ContextGraph:
    root: str
    depth: int
    nodes: tuple[ResolvedContext, ...]
    edges: tuple[GraphEdge, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "ctx-graph/v1",
            "root": self.root,
            "depth": self.depth,
            "nodes": [
                {
                    "uri": node.uri,
                    "title": node.item.title if node.item is not None else node.node.manifest.node.name,
                    "kind": node.item.kind if node.item is not None else "node",
                    "project": node.project.entry.project_id,
                }
                for node in self.nodes
            ],
            "edges": [edge.to_dict() for edge in self.edges],
            "warnings": list(self.warnings),
        }


def _local_context(path: Path) -> ResolvedContext:
    ancestry = discover_ancestry(path)
    validation = validate_project(ancestry.project_root)
    node = next(value for value in validation.nodes if value.uri == ancestry.current.uri)
    entry = RegistryEntry(
        validation.project.id,
        validation.project.name,
        validation.project.aliases,
        validation.project_root,
    )
    return ResolvedContext(IndexedProject(entry, validation), node)


def context_graph(
    reference: str | None = None,
    *,
    from_path: Path = Path("."),
    depth: int = 1,
) -> ContextGraph:
    if depth < 0 or depth > MAX_GRAPH_DEPTH:
        raise CtxError(
            "graph.depth-invalid",
            f"graph depth must be between 0 and {MAX_GRAPH_DEPTH}",
            exit_code=1,
        )
    if reference is None:
        start = _local_context(from_path)
    else:
        candidate = Path(reference)
        start = _local_context(candidate) if candidate.exists() else resolve_reference(reference)
    queue: list[tuple[ResolvedContext, int]] = [(start, 0)]
    visited: dict[str, ResolvedContext] = {}
    edges: list[GraphEdge] = []
    warnings: list[str] = []
    while queue:
        current, current_depth = queue.pop(0)
        if current.uri in visited:
            continue
        if len(visited) >= MAX_GRAPH_NODES:
            warnings.append(f"graph truncated at {MAX_GRAPH_NODES} nodes")
            break
        visited[current.uri] = current
        if current_depth >= depth:
            continue
        for link in current.node.manifest.links:
            try:
                parsed = parse_ctx_uri(link.target)
                if parsed.project_id == current.project.entry.project_id:
                    node_uri = str(ContextUri(parsed.project_id, parsed.node_ids))
                    loaded = next(
                        (
                            value
                            for value in current.project.validation.nodes
                            if value.uri == node_uri
                        ),
                        None,
                    )
                    if loaded is None:
                        raise CtxError(
                            "reference.unresolved",
                            f"local graph link is unresolved: {link.target}",
                            exit_code=2,
                        )
                    item = None
                    if parsed.item_id is not None:
                        item = next(
                            (
                                value
                                for value in loaded.manifest.items
                                if value.id == parsed.item_id
                            ),
                            None,
                        )
                        if item is None:
                            raise CtxError(
                                "reference.unresolved",
                                f"local graph item is unresolved: {link.target}",
                                exit_code=2,
                            )
                    target = ResolvedContext(current.project, loaded, item)
                else:
                    target = resolve_uri(link.target)
                resolved = True
            except CtxError as exc:
                target = None
                resolved = False
                if not link.optional:
                    warnings.append(f"required link unresolved: {link.target} ({exc.code})")
            edges.append(
                GraphEdge(current.node.uri, link.target, link.relation, link.optional, resolved)
            )
            if target is not None and target.uri not in visited:
                queue.append((target, current_depth + 1))
    ordered_nodes = tuple(visited[key] for key in sorted(visited))
    edges.sort(key=lambda value: (value.source, value.relation, value.target))
    return ContextGraph(start.uri, depth, ordered_nodes, tuple(edges), tuple(warnings))
