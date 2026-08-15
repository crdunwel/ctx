from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal


ItemKind = Literal["pattern", "invariant", "decision"]


@dataclass(frozen=True, slots=True)
class Project:
    id: str
    name: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Node:
    id: str
    name: str
    summary: str | None = None


@dataclass(frozen=True, slots=True)
class Artifact:
    path: str
    role: str


@dataclass(frozen=True, slots=True)
class Adoption:
    mode: str
    requires: tuple[str, ...] = ()
    adapt: tuple[str, ...] = ()
    verify: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Item:
    id: str
    kind: ItemKind
    title: str
    summary: str
    artifacts: tuple[str, ...] = ()
    adoption: Adoption | None = None
    reason: str | None = None
    supersedes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Link:
    target: str
    relation: str
    optional: bool = False


@dataclass(frozen=True, slots=True)
class Tracking:
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Manifest:
    version: int
    node: Node
    project: Project | None = None
    artifacts: tuple[Artifact, ...] = ()
    items: tuple[Item, ...] = ()
    links: tuple[Link, ...] = ()
    tracking: Tracking = field(default_factory=Tracking)

    def to_dict(self) -> dict[str, Any]:
        """Return only modeled manifest data, omitting absent optional fields."""
        result: dict[str, Any] = {"version": self.version}
        if self.project is not None:
            result["project"] = {
                "id": self.project.id,
                "name": self.project.name,
                "aliases": list(self.project.aliases),
            }
        node: dict[str, Any] = {"id": self.node.id, "name": self.node.name}
        if self.node.summary is not None:
            node["summary"] = self.node.summary
        result["node"] = node
        if self.artifacts:
            result["artifacts"] = [asdict(value) for value in self.artifacts]
        if self.items:
            rendered_items: list[dict[str, Any]] = []
            for value in self.items:
                item: dict[str, Any] = {
                    "id": value.id,
                    "kind": value.kind,
                    "title": value.title,
                    "summary": value.summary,
                }
                if value.artifacts:
                    item["artifacts"] = list(value.artifacts)
                if value.adoption is not None:
                    adoption: dict[str, Any] = {"mode": value.adoption.mode}
                    for key in ("requires", "adapt", "verify"):
                        entries = getattr(value.adoption, key)
                        if entries:
                            adoption[key] = list(entries)
                    item["adoption"] = adoption
                if value.reason is not None:
                    item["reason"] = value.reason
                if value.supersedes:
                    item["supersedes"] = list(value.supersedes)
                rendered_items.append(item)
            result["items"] = rendered_items
        if self.links:
            rendered_links: list[dict[str, Any]] = []
            for value in self.links:
                link: dict[str, Any] = {
                    "target": value.target,
                    "relation": value.relation,
                }
                if value.optional:
                    link["optional"] = True
                rendered_links.append(link)
            result["links"] = rendered_links
        if self.tracking.include or self.tracking.exclude:
            tracking: dict[str, Any] = {}
            if self.tracking.include:
                tracking["include"] = list(self.tracking.include)
            if self.tracking.exclude:
                tracking["exclude"] = list(self.tracking.exclude)
            result["tracking"] = tracking
        return result


@dataclass(frozen=True, slots=True)
class ManifestDocument:
    path: Path
    node_dir: Path
    raw_text: str
    raw_data: dict[str, Any] | None
    manifest: Manifest | None
    diagnostics: tuple[Any, ...] = ()


@dataclass(frozen=True, slots=True)
class LoadedNode:
    document: ManifestDocument
    uri: str

    @property
    def manifest(self) -> Manifest:
        assert self.document.manifest is not None
        return self.document.manifest
