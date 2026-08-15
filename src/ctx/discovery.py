from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .diagnostics import CtxError, Diagnostic, NotFoundError, UnsafePathError
from .models import LoadedNode, ManifestDocument, Project
from .paths import (
    absolute_lexical,
    discovery_start,
    is_within,
    require_safe_context_file,
)
from .schema import parse_manifest
from .uri import node_uri
from .yamlio import load_yaml


MANIFEST_PARTS = (".ctx", "context.yaml")
PRUNED_DIRECTORIES = {
    ".git",
    ".ctx",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "vendor",
}
MAX_SCAN_DIRECTORIES = 100_000
MAX_SCAN_MANIFESTS = 10_000


@dataclass(frozen=True, slots=True)
class Ancestry:
    requested_path: Path
    resolved_path: Path
    project_root: Path
    project: Project
    nodes: tuple[LoadedNode, ...]

    @property
    def current(self) -> LoadedNode:
        return self.nodes[-1]


def manifest_path(node_dir: Path) -> Path:
    return node_dir.joinpath(*MANIFEST_PARTS)


def read_manifest_document(path: Path) -> ManifestDocument:
    require_safe_context_file(path)
    try:
        raw_text, raw_data = load_yaml(path)
    except CtxError as exc:
        diagnostic = Diagnostic("error", exc.code, exc.message, path)
        return ManifestDocument(path, path.parent.parent, "", None, None, (diagnostic,))
    manifest, diagnostics = parse_manifest(raw_data, path, raw_text=raw_text)
    return ManifestDocument(
        path,
        path.parent.parent,
        raw_text,
        raw_data if type(raw_data) is dict else None,
        manifest,
        diagnostics,
    )


def _invalid_document_error(document: ManifestDocument) -> CtxError:
    errors = [value for value in document.diagnostics if value.severity == "error"]
    detail = errors[0].message if errors else "manifest is invalid"
    return CtxError(
        "manifest.invalid", f"invalid context manifest {document.path}: {detail}", exit_code=1
    )


def _find_lexical_root(start_dir: Path) -> tuple[Path, ManifestDocument]:
    saw_manifest: ManifestDocument | None = None
    current = start_dir
    while True:
        candidate = manifest_path(current)
        if candidate.exists() or candidate.is_symlink():
            document = read_manifest_document(candidate)
            saw_manifest = saw_manifest or document
            if document.manifest is not None and document.manifest.project is not None:
                return current, document
        parent = current.parent
        if parent == current:
            break
        current = parent
    if saw_manifest is not None:
        if saw_manifest.manifest is None:
            raise _invalid_document_error(saw_manifest)
        raise CtxError(
            "manifest.orphaned",
            f"found a context node but no project root above {start_dir}",
            exit_code=1,
        )
    raise NotFoundError("project.not-found", f"no ctx project contains {start_dir}")


def find_project_root(path: Path) -> tuple[Path, Project]:
    requested, start_dir = discovery_start(path)
    # Search physical ancestors first. This prevents a symlinked child from
    # silently switching discovery into a different project.
    physical_start = requested.parent if requested.is_file() else requested
    physical_ancestors = [physical_start, *physical_start.parents]
    lexical_enclosing: tuple[Path, ManifestDocument] | None = None
    for directory in physical_ancestors:
        if directory.is_symlink():
            continue
        candidate = manifest_path(directory)
        if candidate.exists() or candidate.is_symlink():
            document = read_manifest_document(candidate)
            if document.manifest is not None and document.manifest.project is not None:
                lexical_enclosing = (directory.resolve(strict=True), document)
                break
    if lexical_enclosing is not None:
        lexical_root, root_document = lexical_enclosing
    else:
        lexical_root, root_document = _find_lexical_root(start_dir)
    try:
        resolved_root = lexical_root.resolve(strict=True)
        resolved_requested = requested.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UnsafePathError("path.resolve-failed", f"cannot resolve project path safely: {exc}") from exc
    if not is_within(resolved_requested, resolved_root):
        raise UnsafePathError(
            "path.symlink-escape",
            f"path resolves outside its containing ctx project: {requested}",
        )
    assert root_document.manifest is not None
    assert root_document.manifest.project is not None
    return resolved_root, root_document.manifest.project


def _directories_between(root: Path, target: Path) -> Iterable[Path]:
    relative = target.relative_to(root)
    current = root
    yield current
    for part in relative.parts:
        current = current / part
        yield current


def discover_ancestry(path: Path) -> Ancestry:
    requested, _ = discovery_start(path)
    project_root, project = find_project_root(requested)
    try:
        resolved = requested.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UnsafePathError("path.resolve-failed", f"cannot resolve path safely: {exc}") from exc
    target_dir = resolved.parent if resolved.is_file() else resolved
    documents: list[ManifestDocument] = []
    for directory in _directories_between(project_root, target_dir):
        candidate = manifest_path(directory)
        if candidate.exists() or candidate.is_symlink():
            document = read_manifest_document(candidate)
            if document.manifest is None:
                raise _invalid_document_error(document)
            documents.append(document)
    if not documents:
        raise NotFoundError("project.not-found", f"no ctx project contains {requested}")
    root_document = documents[0]
    assert root_document.manifest is not None
    if root_document.manifest.project is None:
        raise CtxError(
            "manifest.root-project-missing",
            f"root manifest does not define a project: {root_document.path}",
            exit_code=1,
        )
    semantic_ids: list[str] = []
    nodes: list[LoadedNode] = []
    for index, document in enumerate(documents):
        assert document.manifest is not None
        manifest = document.manifest
        if index == 0:
            if manifest.node.id != "root":
                raise CtxError(
                    "manifest.root-id",
                    f"root node ID must be 'root': {document.path}",
                    exit_code=1,
                )
        else:
            if manifest.project is not None:
                raise CtxError(
                    "manifest.nested-project",
                    f"nested node cannot redefine project identity: {document.path}",
                    exit_code=1,
                )
            if manifest.node.id == "root":
                raise CtxError(
                    "manifest.nested-root-id",
                    f"nested node ID cannot be 'root': {document.path}",
                    exit_code=1,
                )
            semantic_ids.append(manifest.node.id)
        nodes.append(LoadedNode(document, node_uri(project.id, tuple(semantic_ids))))
    return Ancestry(requested, resolved, project_root, project, tuple(nodes))


def scan_project_documents(project_root: Path) -> tuple[ManifestDocument, ...]:
    root = project_root.resolve(strict=True)
    documents: list[ManifestDocument] = []
    scan_errors: list[OSError] = []
    visited_directories = 0
    for current_text, directories, _files in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=scan_errors.append,
    ):
        visited_directories += 1
        if visited_directories > MAX_SCAN_DIRECTORIES:
            raise CtxError(
                "discovery.too-broad",
                f"project scan exceeded {MAX_SCAN_DIRECTORIES} directories",
                exit_code=4,
            )
        current = Path(current_text)
        safe_directories: list[str] = []
        for name in sorted(directories):
            child = current / name
            if name in PRUNED_DIRECTORIES or child.is_symlink():
                continue
            safe_directories.append(name)
        directories[:] = safe_directories
        candidate = manifest_path(current)
        if candidate.exists() or candidate.is_symlink():
            documents.append(read_manifest_document(candidate))
            if len(documents) > MAX_SCAN_MANIFESTS:
                raise CtxError(
                    "discovery.too-many-manifests",
                    f"project scan exceeded {MAX_SCAN_MANIFESTS} context manifests",
                    exit_code=4,
                )
    if scan_errors:
        first = scan_errors[0]
        raise CtxError(
            "discovery.read-failed",
            f"cannot completely scan project {root}: {first}",
            exit_code=4,
        )
    documents.sort(key=lambda value: (len(value.node_dir.relative_to(root).parts), value.node_dir.as_posix()))
    return tuple(documents)


def assign_node_uris(
    project_root: Path, project: Project, documents: Iterable[ManifestDocument]
) -> tuple[LoadedNode, ...]:
    root = project_root.resolve(strict=True)
    valid = [document for document in documents if document.manifest is not None]
    by_directory = {document.node_dir.resolve(strict=True): document for document in valid}
    result: list[LoadedNode] = []
    for document in valid:
        directory = document.node_dir.resolve(strict=True)
        if directory == root:
            semantic_ids: tuple[str, ...] = ()
        else:
            ancestors: list[ManifestDocument] = []
            current = directory.parent
            while is_within(current, root):
                parent_document = by_directory.get(current)
                if parent_document is not None and current != root:
                    ancestors.append(parent_document)
                if current == root:
                    break
                current = current.parent
            ancestors.reverse()
            semantic_ids = tuple(
                [parent.manifest.node.id for parent in ancestors if parent.manifest is not None]
                + [document.manifest.node.id]
            )
        result.append(LoadedNode(document, node_uri(project.id, semantic_ids)))
    result.sort(key=lambda value: (value.uri.count("/"), value.uri, str(value.document.path)))
    return tuple(result)
