from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .diagnostics import CtxError, NotFoundError, UnsafePathError
from .paths import normalize_alias
from .uri import require_id
from .validation import ValidationResult, validate_project


REGISTRY_VERSION = 1
MAX_REGISTRY_BYTES = 4_194_304
POLICIES = {"code-allowed", "conceptual-only", "reference-only", "prohibited"}
TRUST_VALUES = {"trusted", "untrusted"}


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    project_id: str
    name: str
    aliases: tuple[str, ...]
    root: Path
    collection: str | None = None
    trust: str = "trusted"
    reuse_policy: str = "code-allowed"

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "name": self.name,
            "aliases": list(self.aliases),
            "root": str(self.root),
        }
        if self.collection is not None:
            value["collection"] = self.collection
        if self.trust != "trusted":
            value["trust"] = self.trust
        if self.reuse_policy != "code-allowed":
            value["reuse_policy"] = self.reuse_policy
        return value


@dataclass(frozen=True, slots=True)
class Registry:
    path: Path
    projects: tuple[RegistryEntry, ...]

    def by_id(self) -> dict[str, RegistryEntry]:
        return {entry.project_id: entry for entry in self.projects}


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    action: str
    entry: RegistryEntry
    validation: ValidationResult
    registry_path: Path
    previous_entry: RegistryEntry | None = None
    registry_preexisting: bool = False


def ctx_home() -> Path:
    raw = os.environ.get("CTX_HOME")
    candidate = Path(raw).expanduser() if raw else Path.home() / ".ctx"
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return Path(os.path.abspath(candidate))


def registry_path() -> Path:
    return ctx_home() / "registry.json"


def _empty_registry(path: Path | None = None) -> Registry:
    return Registry(path or registry_path(), ())


def _require_string(value: object, label: str) -> str:
    if type(value) is not str or not value.strip():
        raise CtxError("registry.invalid", f"{label} must be a non-empty string", exit_code=4)
    return value


def _parse_entry(project_id: str, raw: object) -> RegistryEntry:
    require_id(project_id, "registered project ID")
    if type(raw) is not dict:
        raise CtxError("registry.invalid", f"registry entry {project_id} must be an object", exit_code=4)
    allowed = {"name", "aliases", "root", "collection", "trust", "reuse_policy"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise CtxError(
            "registry.invalid",
            f"registry entry {project_id} has unknown field {unknown[0]}",
            exit_code=4,
        )
    name = _require_string(raw.get("name"), f"registry entry {project_id} name")
    aliases_raw = raw.get("aliases")
    if type(aliases_raw) is not list or any(type(value) is not str or not value.strip() for value in aliases_raw):
        raise CtxError(
            "registry.invalid",
            f"registry entry {project_id} aliases must be a string list",
            exit_code=4,
        )
    root_text = _require_string(raw.get("root"), f"registry entry {project_id} root")
    root = Path(root_text)
    if not root.is_absolute():
        raise CtxError(
            "registry.invalid",
            f"registry entry {project_id} root must be absolute",
            exit_code=4,
        )
    collection_raw = raw.get("collection")
    collection = None if collection_raw is None else _require_string(
        collection_raw, f"registry entry {project_id} collection"
    )
    trust = raw.get("trust", "trusted")
    reuse = raw.get("reuse_policy", "code-allowed")
    if trust not in TRUST_VALUES:
        raise CtxError("registry.invalid", f"invalid trust value for {project_id}", exit_code=4)
    if reuse not in POLICIES:
        raise CtxError("registry.invalid", f"invalid reuse policy for {project_id}", exit_code=4)
    aliases = tuple(aliases_raw)
    normalized = [normalize_alias(value) for value in aliases]
    if len(set(normalized)) != len(normalized):
        raise CtxError("registry.invalid", f"duplicate aliases for {project_id}", exit_code=4)
    return RegistryEntry(project_id, name, aliases, root, collection, trust, reuse)


def load_registry(*, missing_ok: bool = True) -> Registry:
    path = registry_path()
    if not path.exists() and not path.is_symlink():
        if missing_ok:
            return _empty_registry(path)
        raise NotFoundError("registry.not-found", f"ctx registry does not exist: {path}")
    if path.is_symlink():
        raise UnsafePathError("registry.symlink", f"registry cannot be a symlink: {path}")
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsafePathError("registry.not-file", f"registry is not a regular file: {path}")
        if metadata.st_size > MAX_REGISTRY_BYTES:
            raise CtxError("registry.too-large", "registry exceeds its safety limit", exit_code=4)
        raw_bytes = path.read_bytes()
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError("registry.read-failed", f"cannot read registry {path}: {exc}", exit_code=4) from exc
    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CtxError("registry.invalid", f"registry is not valid UTF-8 JSON: {exc}", exit_code=4) from exc
    if type(raw) is not dict or raw.get("version") != REGISTRY_VERSION or type(raw.get("projects")) is not dict:
        raise CtxError("registry.invalid", "registry must contain version 1 and a projects object", exit_code=4)
    if set(raw) != {"version", "projects"}:
        raise CtxError("registry.invalid", "registry contains unknown top-level fields", exit_code=4)
    projects = tuple(
        _parse_entry(project_id, value)
        for project_id, value in sorted(raw["projects"].items())
    )
    _assert_lookup_unique(projects, operational=True)
    return Registry(path, projects)


def _lookup_keys(entry: RegistryEntry) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            [normalize_alias(entry.project_id), normalize_alias(entry.name)]
            + [normalize_alias(value) for value in entry.aliases]
        )
    )


def _assert_lookup_unique(entries: Iterable[RegistryEntry], *, operational: bool) -> None:
    owners: dict[str, str] = {}
    for entry in entries:
        for key in _lookup_keys(entry):
            owner = owners.get(key)
            if owner is not None and owner != entry.project_id:
                raise CtxError(
                    "registry.collision",
                    f"lookup name {key!r} belongs to both {owner} and {entry.project_id}",
                    exit_code=4 if operational else 3,
                )
            owners[key] = entry.project_id


def _write_registry(path: Path, entries: Iterable[RegistryEntry]) -> None:
    ordered = sorted(entries, key=lambda value: value.project_id)
    _assert_lookup_unique(ordered, operational=False)
    payload = {
        "version": REGISTRY_VERSION,
        "projects": {entry.project_id: entry.to_dict() for entry in ordered},
    }
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    parent = path.parent
    if parent.exists() and parent.is_symlink():
        raise UnsafePathError("registry.home-symlink", f"CTX_HOME cannot be a symlink: {parent}")
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir():
            raise UnsafePathError("registry.home-unsafe", f"CTX_HOME is unsafe: {parent}")
        descriptor, temporary_name = tempfile.mkstemp(dir=parent, prefix=".registry.", suffix=".tmp")
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    except CtxError:
        raise
    except OSError as exc:
        raise CtxError("registry.write-failed", f"cannot update registry {path}: {exc}", exit_code=4) from exc


def register_project(path: Path) -> RegistrationResult:
    validation = validate_project(path, strict=True)
    if not validation.valid:
        first = (validation.errors or validation.strict_failures)[0]
        raise CtxError(
            "registry.validation-failed",
            f"project must pass strict validation before registration: {first.code}: {first.message}",
            exit_code=3 if validation.unsafe else 1,
        )
    root = validation.project_root.resolve(strict=True)
    project = validation.project
    registry = load_registry()
    registry_preexisting = registry.path.exists()
    existing = registry.by_id().get(project.id)
    if existing is not None and existing.root.resolve(strict=False) != root:
        raise UnsafePathError(
            "registry.project-conflict",
            f"project ID {project.id} is already registered at {existing.root}",
        )
    for entry in registry.projects:
        if entry.project_id != project.id and entry.root.resolve(strict=False) == root:
            raise UnsafePathError(
                "registry.root-conflict",
                f"checkout {root} is already registered as {entry.project_id}",
            )
    replacement = RegistryEntry(
        project.id,
        project.name,
        project.aliases,
        root,
        existing.collection if existing else None,
        existing.trust if existing else "trusted",
        existing.reuse_policy if existing else "code-allowed",
    )
    updated = [entry for entry in registry.projects if entry.project_id != project.id] + [replacement]
    _assert_lookup_unique(updated, operational=False)
    action = "unchanged" if existing == replacement else ("updated" if existing else "registered")
    if action != "unchanged":
        _write_registry(registry.path, updated)
    return RegistrationResult(
        action,
        replacement,
        validation,
        registry.path,
        existing,
        registry_preexisting,
    )


def rollback_registration(result: RegistrationResult) -> None:
    """Undo only the exact registry entry written by ``register_project``."""

    if result.action == "unchanged":
        return
    if result.action not in {"registered", "updated"}:
        raise CtxError(
            "registry.rollback-failed",
            f"cannot roll back unknown registration action {result.action!r}",
            exit_code=4,
        )
    registry = load_registry()
    if registry.path != result.registry_path:
        raise CtxError(
            "registry.rollback-failed",
            "CTX_HOME changed before registry rollback",
            exit_code=4,
        )
    current = registry.by_id().get(result.entry.project_id)
    if current == result.previous_entry:
        return
    if current != result.entry:
        raise CtxError(
            "registry.rollback-failed",
            "registered project changed concurrently and was not rolled back: "
            f"{result.entry.project_id}",
            exit_code=4,
        )
    restored = [
        entry
        for entry in registry.projects
        if entry.project_id != result.entry.project_id
    ]
    if result.previous_entry is not None:
        restored.append(result.previous_entry)
    if not result.registry_preexisting and not restored:
        verified = load_registry(missing_ok=False)
        if verified.path != registry.path or verified.projects != registry.projects:
            raise CtxError(
                "registry.rollback-failed",
                "registry changed concurrently and was not removed during rollback",
                exit_code=4,
            )
        try:
            registry.path.unlink()
        except OSError as exc:
            raise CtxError(
                "registry.rollback-failed",
                f"cannot remove newly created registry {registry.path}: {exc}",
                exit_code=4,
            ) from exc
        return
    _write_registry(registry.path, restored)


def resolve_project(reference: str, *, registry: Registry | None = None) -> RegistryEntry:
    selected = registry or load_registry()
    exact = selected.by_id().get(reference)
    if exact is not None:
        return exact
    key = normalize_alias(reference)
    matches = [entry for entry in selected.projects if key in _lookup_keys(entry)]
    if not matches:
        raise NotFoundError("reference.unresolved", f"no registered project matches {reference!r}")
    if len(matches) > 1:
        candidates = ", ".join(entry.project_id for entry in matches)
        raise NotFoundError("reference.ambiguous", f"reference {reference!r} is ambiguous: {candidates}")
    return matches[0]


def unregister_project(reference: str) -> RegistryEntry:
    registry = load_registry(missing_ok=False)
    entry = resolve_project(reference, registry=registry)
    remaining = [value for value in registry.projects if value.project_id != entry.project_id]
    _write_registry(registry.path, remaining)
    return entry
