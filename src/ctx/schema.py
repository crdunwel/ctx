from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, cast

from .diagnostics import Diagnostic
from .models import Adoption, Artifact, Item, Link, Manifest, Node, Project, Tracking
from .paths import normalize_alias
from .uri import is_valid_id


TOP_KEYS = {"version", "project", "node", "artifacts", "items", "links", "tracking"}
PROJECT_KEYS = {"id", "name", "aliases"}
NODE_KEYS = {"id", "name", "summary"}
ARTIFACT_KEYS = {"path", "role"}
ITEM_COMMON_KEYS = {"id", "kind", "title", "summary", "artifacts"}
ADOPTION_KEYS = {"mode", "requires", "adapt", "verify"}
LINK_KEYS = {"target", "relation", "optional"}
TRACKING_KEYS = {"include", "exclude"}
ITEM_KINDS = {"pattern", "invariant", "decision"}
ADOPTION_MODES = {"adapt", "copy", "reference"}
LINK_RELATIONS = {
    "depends_on",
    "governed_by",
    "conforms_to",
    "inspired_by",
    "derived_from",
    "tested_by",
    "documents",
    "supersedes",
    "related_to",
}


class SchemaReader:
    def __init__(self, manifest_path: Path) -> None:
        self.manifest_path = manifest_path
        self.diagnostics: list[Diagnostic] = []

    def error(self, code: str, message: str, field: str | None = None) -> None:
        self.diagnostics.append(
            Diagnostic("error", code, message, self.manifest_path, field)
        )

    def warning(
        self, code: str, message: str, field: str | None = None, *, strict: bool = True
    ) -> None:
        self.diagnostics.append(
            Diagnostic(
                "warning",
                code,
                message,
                self.manifest_path,
                field,
                fails_strict=strict,
            )
        )

    def mapping(self, value: Any, field: str) -> dict[str, Any] | None:
        if type(value) is not dict:
            self.error("schema.type", f"{field} must be a mapping", field)
            return None
        if any(type(key) is not str for key in value):
            self.error("schema.key-type", f"{field} keys must be strings", field)
            return None
        return cast(dict[str, Any], value)

    def unknown(self, value: dict[str, Any], allowed: set[str], field: str) -> None:
        for key in sorted(set(value) - allowed):
            pointer = f"{field}.{key}" if field else key
            self.warning("schema.unknown-field", f"unknown field: {pointer}", pointer)

    def string(
        self, value: dict[str, Any], key: str, field: str, *, required: bool = True
    ) -> str | None:
        pointer = f"{field}.{key}" if field else key
        if key not in value:
            if required:
                self.error("schema.required", f"missing required field: {pointer}", pointer)
            return None
        item = value[key]
        if type(item) is not str or not item.strip():
            self.error("schema.type", f"{pointer} must be a non-empty string", pointer)
            return None
        return cast(str, item)

    def string_list(
        self,
        value: dict[str, Any],
        key: str,
        field: str,
        *,
        required: bool = False,
    ) -> tuple[str, ...]:
        pointer = f"{field}.{key}" if field else key
        if key not in value:
            if required:
                self.error("schema.required", f"missing required field: {pointer}", pointer)
            return ()
        entries = value[key]
        if type(entries) is not list:
            self.error("schema.type", f"{pointer} must be a list of strings", pointer)
            return ()
        result: list[str] = []
        for index, entry in enumerate(entries):
            item_pointer = f"{pointer}[{index}]"
            if type(entry) is not str or not entry.strip():
                self.error("schema.type", f"{item_pointer} must be a non-empty string", item_pointer)
            else:
                result.append(entry)
        return tuple(result)

    def identity(self, value: str | None, field: str) -> str | None:
        if value is not None and not is_valid_id(value):
            self.error(
                "identity.invalid",
                f"{field} must use lowercase letters, digits, and single hyphens only",
                field,
            )
            return None
        return value


def _summary_warning(reader: SchemaReader, value: str | None, field: str) -> None:
    if value is not None and len(value) > 500:
        reader.warning("summary.too-long", f"{field} exceeds 500 characters", field)


def _parse_project(reader: SchemaReader, value: Any) -> Project | None:
    data = reader.mapping(value, "project")
    if data is None:
        return None
    reader.unknown(data, PROJECT_KEYS, "project")
    project_id = reader.identity(reader.string(data, "id", "project"), "project.id")
    name = reader.string(data, "name", "project")
    aliases = reader.string_list(data, "aliases", "project", required=True)
    normalized: set[str] = set()
    for index, alias in enumerate(aliases):
        key = normalize_alias(alias)
        if not key:
            reader.error("alias.empty", "project alias normalizes to an empty value", f"project.aliases[{index}]")
        elif key in normalized:
            reader.error("alias.duplicate", f"duplicate project alias: {alias}", f"project.aliases[{index}]")
        normalized.add(key)
    if project_id is None or name is None:
        return None
    return Project(project_id, name, aliases)


def _parse_node(reader: SchemaReader, value: Any) -> Node | None:
    data = reader.mapping(value, "node")
    if data is None:
        return None
    reader.unknown(data, NODE_KEYS, "node")
    node_id = reader.identity(reader.string(data, "id", "node"), "node.id")
    name = reader.string(data, "name", "node")
    summary = reader.string(data, "summary", "node", required=False)
    _summary_warning(reader, summary, "node.summary")
    if node_id is None or name is None:
        return None
    return Node(node_id, name, summary)


def _parse_artifacts(reader: SchemaReader, root: dict[str, Any]) -> tuple[Artifact, ...]:
    if "artifacts" not in root:
        return ()
    values = root["artifacts"]
    if type(values) is not list:
        reader.error("schema.type", "artifacts must be a list", "artifacts")
        return ()
    result: list[Artifact] = []
    for index, raw in enumerate(values):
        pointer = f"artifacts[{index}]"
        data = reader.mapping(raw, pointer)
        if data is None:
            continue
        reader.unknown(data, ARTIFACT_KEYS, pointer)
        path = reader.string(data, "path", pointer)
        role = reader.string(data, "role", pointer)
        if role is not None and (
            len(role) > 500 or role.count(chr(96)) >= 3 or role.count("\n") >= 4
        ):
            reader.warning(
                "artifact.role-copied-source",
                "artifact role may contain copied source instead of a concise explanation",
                f"{pointer}.role",
            )
        if path is not None and role is not None:
            result.append(Artifact(path, role))
    return tuple(result)


def _parse_adoption(reader: SchemaReader, raw: Any, pointer: str) -> Adoption | None:
    data = reader.mapping(raw, pointer)
    if data is None:
        return None
    reader.unknown(data, ADOPTION_KEYS, pointer)
    mode = reader.string(data, "mode", pointer)
    if mode is not None and mode not in ADOPTION_MODES:
        reader.error("adoption.mode-invalid", f"unsupported adoption mode: {mode}", f"{pointer}.mode")
        mode = None
    requires = reader.string_list(data, "requires", pointer)
    adapt = reader.string_list(data, "adapt", pointer)
    verify = reader.string_list(data, "verify", pointer)
    if mode is None:
        return None
    return Adoption(mode, requires, adapt, verify)


def _parse_items(reader: SchemaReader, root: dict[str, Any]) -> tuple[Item, ...]:
    if "items" not in root:
        return ()
    values = root["items"]
    if type(values) is not list:
        reader.error("schema.type", "items must be a list", "items")
        return ()
    if len(values) > 20:
        reader.warning("items.too-many", "manifest contains more than 20 durable items", "items")
    result: list[Item] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(values):
        pointer = f"items[{index}]"
        data = reader.mapping(raw, pointer)
        if data is None:
            continue
        raw_kind = data.get("kind")
        allowed = set(ITEM_COMMON_KEYS)
        if raw_kind == "pattern":
            allowed.add("adoption")
        elif raw_kind == "decision":
            allowed.update({"reason", "supersedes"})
        reader.unknown(data, allowed, pointer)
        item_id = reader.identity(reader.string(data, "id", pointer), f"{pointer}.id")
        kind = reader.string(data, "kind", pointer)
        title = reader.string(data, "title", pointer)
        summary = reader.string(data, "summary", pointer)
        _summary_warning(reader, summary, f"{pointer}.summary")
        if kind is not None and kind not in ITEM_KINDS:
            reader.error("item.kind-invalid", f"unsupported item kind: {kind}", f"{pointer}.kind")
            kind = None
        if item_id is not None:
            if item_id in seen_ids:
                reader.error("item.id-duplicate", f"duplicate item ID: {item_id}", f"{pointer}.id")
            seen_ids.add(item_id)
        artifacts = reader.string_list(data, "artifacts", pointer)
        adoption: Adoption | None = None
        reason: str | None = None
        supersedes: tuple[str, ...] = ()
        if kind == "pattern":
            if "adoption" in data:
                adoption = _parse_adoption(reader, data["adoption"], f"{pointer}.adoption")
        elif kind == "decision":
            reason = reader.string(data, "reason", pointer, required=False)
            supersedes = reader.string_list(data, "supersedes", pointer)
        if None not in (item_id, kind, title, summary):
            result.append(
                Item(
                    cast(str, item_id),
                    cast(Any, kind),
                    cast(str, title),
                    cast(str, summary),
                    artifacts,
                    adoption,
                    reason,
                    supersedes,
                )
            )
    return tuple(result)


def _parse_links(reader: SchemaReader, root: dict[str, Any]) -> tuple[Link, ...]:
    if "links" not in root:
        return ()
    values = root["links"]
    if type(values) is not list:
        reader.error("schema.type", "links must be a list", "links")
        return ()
    result: list[Link] = []
    for index, raw in enumerate(values):
        pointer = f"links[{index}]"
        data = reader.mapping(raw, pointer)
        if data is None:
            continue
        reader.unknown(data, LINK_KEYS, pointer)
        target = reader.string(data, "target", pointer)
        relation = reader.string(data, "relation", pointer)
        optional_raw = data.get("optional", False)
        optional: bool | None
        if type(optional_raw) is not bool:
            reader.error("schema.type", f"{pointer}.optional must be a boolean", f"{pointer}.optional")
            optional = None
        else:
            optional = optional_raw
        if relation is not None and relation not in LINK_RELATIONS:
            reader.error("link.relation-invalid", f"unsupported link relation: {relation}", f"{pointer}.relation")
            relation = None
        if target is not None and relation is not None and optional is not None:
            result.append(Link(target, relation, optional))
    return tuple(result)


def _parse_tracking(reader: SchemaReader, root: dict[str, Any]) -> Tracking:
    if "tracking" not in root:
        return Tracking()
    data = reader.mapping(root["tracking"], "tracking")
    if data is None:
        return Tracking()
    reader.unknown(data, TRACKING_KEYS, "tracking")
    return Tracking(
        reader.string_list(data, "include", "tracking"),
        reader.string_list(data, "exclude", "tracking"),
    )


def parse_manifest(
    raw_data: Any, manifest_path: Path, *, raw_text: str = ""
) -> tuple[Manifest | None, tuple[Diagnostic, ...]]:
    reader = SchemaReader(manifest_path)
    root = reader.mapping(raw_data, "manifest")
    if root is None:
        return None, tuple(reader.diagnostics)
    reader.unknown(root, TOP_KEYS, "")
    version = root.get("version")
    if type(version) is not int or version != 1:
        reader.error("schema.version", "version must be the integer 1", "version")
    project = _parse_project(reader, root["project"]) if "project" in root else None
    node = _parse_node(reader, root.get("node"))
    artifacts = _parse_artifacts(reader, root)
    items = _parse_items(reader, root)
    links = _parse_links(reader, root)
    tracking = _parse_tracking(reader, root)
    if len(raw_text) > 16_000:
        reader.warning(
            "manifest.too-large",
            "manifest is larger than roughly 4,000 estimated tokens",
        )
    if any(diagnostic.severity == "error" for diagnostic in reader.diagnostics):
        return None, tuple(reader.diagnostics)
    assert type(version) is int and node is not None
    return (
        Manifest(version, node, project, artifacts, items, links, tracking),
        tuple(reader.diagnostics),
    )


def diagnostic_errors(diagnostics: Iterable[Diagnostic]) -> bool:
    return any(value.severity == "error" for value in diagnostics)
