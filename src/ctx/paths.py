from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path, PurePosixPath, PureWindowsPath

from .diagnostics import CtxError, UnsafePathError


SECRET_FILE_NAMES = {
    ".env",
    "credentials.json",
    "service-account.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}
SECRET_DIR_NAMES = {".aws", ".ssh"}
SECRET_SUFFIXES = {".key", ".p12", ".pfx", ".pem"}
SAFE_ENV_SUFFIXES = {".example", ".sample", ".template"}


def absolute_lexical(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def existing_directory(path: Path) -> Path:
    candidate = absolute_lexical(path)
    if not candidate.exists():
        raise CtxError("path.not-found", f"path does not exist: {candidate}", exit_code=1)
    if not candidate.is_dir():
        raise CtxError("path.not-directory", f"path is not a directory: {candidate}", exit_code=1)
    return candidate


def discovery_start(path: Path) -> tuple[Path, Path]:
    candidate = absolute_lexical(path)
    if not candidate.exists():
        raise CtxError("path.not-found", f"path does not exist: {candidate}", exit_code=1)
    start_dir = candidate.parent if candidate.is_file() and not candidate.is_symlink() else candidate
    return candidate, start_dir


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def require_safe_context_file(path: Path) -> None:
    if path.parent.is_symlink() or path.is_symlink():
        raise UnsafePathError(
            "manifest.symlink", f"context manifests and their .ctx directory cannot be symlinks: {path}"
        )
    if path.exists() and not path.is_file():
        raise UnsafePathError("manifest.not-file", f"manifest is not a regular file: {path}")


def slugify(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", normalized.lower()).strip("-")


def normalize_alias(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _validate_authored_path(value: str, *, allow_glob: bool) -> PurePosixPath:
    if not value or value.strip() != value or "\x00" in value or "\\" in value:
        raise UnsafePathError("path.unsafe", f"unsafe relative path: {value!r}")
    if any(ord(char) < 32 for char in value):
        raise UnsafePathError("path.unsafe", f"unsafe relative path: {value!r}")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise UnsafePathError("path.absolute", f"path must be project-relative: {value}")
    if not allow_glob and any(char in value for char in "*?["):
        raise UnsafePathError("path.glob-disallowed", f"artifact path cannot be a glob: {value}")
    return posix


def lexical_project_path(
    node_dir: Path, value: str, project_root: Path, *, allow_glob: bool = False
) -> Path:
    _validate_authored_path(value, allow_glob=allow_glob)
    candidate = Path(os.path.abspath(os.path.join(node_dir, value)))
    root = absolute_lexical(project_root)
    if not is_within(candidate, root):
        raise UnsafePathError(
            "path.escape", f"path escapes the project root: {value} (from {node_dir})"
        )
    return candidate


def longest_literal_glob_prefix(value: str) -> str:
    """Return the path prefix before the first glob-bearing component."""
    parts = value.split("/")
    literal: list[str] = []
    for part in parts:
        if any(character in part for character in "*?["):
            break
        literal.append(part)
    return "/".join(literal) or "."


def require_safe_tracking_path(node_dir: Path, value: str, project_root: Path) -> Path:
    candidate = lexical_project_path(node_dir, value, project_root, allow_glob=True)
    prefix = longest_literal_glob_prefix(value)
    try:
        resolved_prefix = lexical_project_path(node_dir, prefix, project_root).resolve(
            strict=False
        )
        resolved_root = project_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UnsafePathError(
            "path.symlink-invalid", f"cannot safely resolve tracking path {value}: {exc}"
        ) from exc
    if not is_within(resolved_prefix, resolved_root):
        raise UnsafePathError(
            "path.symlink-escape", f"tracking path resolves outside the project: {value}"
        )
    return candidate


def resolved_project_path(
    node_dir: Path, value: str, project_root: Path, *, require_exists: bool = True
) -> Path:
    candidate = lexical_project_path(node_dir, value, project_root)
    try:
        resolved = (node_dir / value).resolve(strict=False)
        resolved_root = project_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise UnsafePathError("path.symlink-invalid", f"cannot safely resolve {value}: {exc}") from exc
    if not is_within(resolved, resolved_root):
        raise UnsafePathError("path.symlink-escape", f"path resolves outside the project: {value}")
    if require_exists and candidate.is_symlink() and not candidate.exists():
        raise UnsafePathError("path.symlink-invalid", f"path is a dangling symlink: {value}")
    return resolved


def has_exact_case(candidate: Path, project_root: Path) -> bool:
    """Check path spelling independently of case-sensitive filesystem behavior."""
    root = project_root.resolve(strict=True)
    try:
        relative = candidate.relative_to(absolute_lexical(project_root))
    except ValueError:
        return False
    current = root
    for part in relative.parts:
        if part in {".", ".."}:
            return False
        try:
            names = {entry.name for entry in os.scandir(current)}
        except OSError:
            return False
        if part not in names:
            return False
        current = current / part
    return True


def is_secret_path(candidate: Path, project_root: Path) -> bool:
    try:
        relative = candidate.relative_to(absolute_lexical(project_root))
    except ValueError:
        return True
    lowered = tuple(part.casefold() for part in relative.parts)
    if any(part in {".ctx", ".git"} for part in lowered):
        return True
    if any(part in SECRET_DIR_NAMES for part in lowered):
        return True
    name = lowered[-1] if lowered else ""
    if name in SECRET_FILE_NAMES:
        return True
    if name.startswith(".env.") and not any(name.endswith(suffix) for suffix in SAFE_ENV_SUFFIXES):
        return True
    return any(name.endswith(suffix) for suffix in SECRET_SUFFIXES)
